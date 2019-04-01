<?php
/*
 * SAML Authentication plugin for LimeSurvey
 * Copyright (C) 2013 Sixto Pablo Martin Garcia <sixto.martin.garcia@gmail.com>
 * License: GNU/GPL License v2 http://www.gnu.org/licenses/gpl-2.0.html
 * URL: https://github.com/pitbulk/limesurvey-saml
 * A plugin of LimeSurvey, a free software. This version may have been modified pursuant
 * to the GNU General Public License, and as distributed it includes or
 * is derivative of works licensed under the GNU General Public License or
 * other free or open source software licenses.
 */

class AuthSAML extends AuthPluginBase
{

	static protected $description = 'SAML authentication plugin';
	static protected $name = 'SAML';

	protected $storage = 'DbStorage';
	protected $ssp = NULL;

	protected $settings = array (
		'simplesamlphp_path'            => array (
			'type'    => 'string',
			'label'   => 'Path to the SimpleSAMLphp folder',
			'default' => '/var/www/simplesamlphp',
		),
		'saml_authsource'               => array (
			'type'    => 'string',
			'label'   => 'SAML authentication source',
			'default' => 'limesurvey',
		),
		'saml_uid_mapping'              => array (
			'type'    => 'string',
			'label'   => 'SAML attributed used as username',
			'default' => 'uid',
		),
		'saml_mail_mapping'             => array (
			'type'    => 'string',
			'label'   => 'SAML attributed used as email',
			'default' => 'mail',
		),
		'saml_name_mapping'             => array (
			'type'    => 'string',
			'label'   => 'SAML attributed used as name',
			'default' => 'cn',
		),
		'saml_group_mapping'            => array (
			'type'    => 'string',
			'label'   => 'SAML attributed used for groups',
			'default' => 'memberof',
		),
		'authtype_base'                 => array (
			'type'    => 'string',
			'label'   => 'Authtype base',
			'default' => 'Authdb',
		),
		'storage_base'                  => array (
			'type'    => 'string',
			'label'   => 'Storage base',
			'default' => 'DbStorage',
		),
		'check_user_group'              => array (
			'type'    => 'checkbox',
			'label'   => 'Check the User Group',
			'default' => TRUE,
		),
		'user_access_group'             => array (
			'type'    => 'string',
			'label'   => 'User Access Group',
			'default' => 'AD-Groupname',
		),
		'auto_create_users'             => array (
			'type'    => 'checkbox',
			'label'   => 'Auto create users',
			'default' => TRUE,
		),
		'auto_create_labelsets'         => array (
			'type'    => 'checkbox',
			'label'   => '- Permissions: Label Sets',
			'default' => FALSE,
		),
		'auto_create_participant_panel' => array (
			'type'    => 'checkbox',
			'label'   => '- Permissions: Participant panel',
			'default' => FALSE,
		),
		'auto_create_settings_plugins'  => array (
			'type'    => 'checkbox',
			'label'   => '- Permissions: Settings & Plugins',
			'default' => FALSE,
		),
		'auto_create_surveys'           => array (
			'type'    => 'checkbox',
			'label'   => '- Permissions: Surveys',
			'default' => TRUE,
		),
		'auto_create_templates'         => array (
			'type'    => 'checkbox',
			'label'   => '- Permissions: Templates',
			'default' => FALSE,
		),
		'auto_create_user_groups'       => array (
			'type'    => 'checkbox',
			'label'   => '- Permissions: User groups',
			'default' => FALSE,
		),
		'auto_update_users'             => array (
			'type'    => 'checkbox',
			'label'   => 'Auto update users',
			'default' => TRUE,
		),
		'force_saml_login'              => array (
			'type'  => 'checkbox',
			'label' => 'Force SAML login.',
		),
		'logout_redirect'               => array (
			'type'    => 'string',
			'label'   => 'Logout Redirect URL',
			'default' => '/admin',
		),
	);

	public function init()
	{
		$this->storage = $this->get('storage_base', NULL, NULL, 'DbStorage');

		// Here you should handle subscribing to the events your plugin will handle
		$this->subscribe('getGlobalBasePermissions');
		//$this->subscribe('beforeHasPermission');
		$this->subscribe('beforeLogin');
		$this->subscribe('afterLoginFormSubmit');

		//$this->subscribe('beforeLogout');
		//$this->subscribe('afterLogout');

		if (!$this->get('force_saml_login', NULL, NULL, FALSE))
		{
			$this->subscribe('newLoginForm');
		}
		$this->subscribe('newUserSession');
	}

	/**
	 * Add AuthLDAP Permission to global Permission
	 */
	public function getGlobalBasePermissions()
	{
		$this->getEvent()->append('globalBasePermissions', array (
			'auth_saml' => array (
				'create'      => FALSE,
				'update'      => FALSE,
				'delete'      => FALSE,
				'import'      => FALSE,
				'export'      => FALSE,
				'title'       => gT("Use SAML authentication"),
				'description' => gT("Use SAML authentication"),
				'img'         => 'usergroup'
			),
		));
	}


	public function beforeLogin()
	{
		$ssp = $this->get_saml_instance();
		if ($this->get('force_saml_login', NULL, NULL, FALSE))
		{
			$ssp->requireAuth();
		}
		if ($ssp->isAuthenticated())
		{
			$this->setAuthPlugin();

			//$this->newUserSession();
			return;
		}
	}

	protected function get_saml_instance()
	{
		if ($this->ssp == NULL)
		{
			$simplesamlphp_path = $this->get('simplesamlphp_path', NULL, NULL, '/var/www/simplesamlphp');
			require_once($simplesamlphp_path . '/lib/_autoload.php');
			$saml_authsource = $this->get('saml_authsource', NULL, NULL, 'limesurvey');
			$this->ssp = new \SimpleSAML_Auth_Simple($saml_authsource);
		}

		return $this->ssp;
	}

	public function newUserSession()
	{
		$dt = date("[Y-m-d H:i:s] ");
		$pfad = dirname(__FILE__) . "/../../";
		$ssp = $this->get_saml_instance();
		$oEvent = $this->getEvent();

		if ($ssp->isAuthenticated())
		{
			$sUser = $this->getUserName();
			$name = $this->getUserCommonName();
			$mail = $this->getUserMail();

			$usergroup = $this->getUserGroup();
			$user_access = FALSE;
			$user_access_group = $this->get('user_access_group', NULL, NULL, 'AD-Groupname');
			$check_user_group = $this->get('check_user_group', NULL, NULL, TRUE);
			error_log($dt . "check: " . $check_user_group . "\n", 3, $pfad . '/debug_saml.log');
			if ($check_user_group)
			{
				if (is_array($usergroup))
				{
					foreach ($usergroup as $key => $value)
					{
						$group_array = explode(',', $value);
						/* Beispiele
					  ADLDS
							CN=G-APP-5650-LimeSurvey,OU=H-5600-APP,OU=TestAD,O=TestAD-AD
						*/
						$groupname = explode('=', $group_array[0]);

						if (is_array($groupname))
						{
							$gruppe = $groupname[1];
							if ($gruppe == $user_access_group)
							{
								$user_access = TRUE;
								break;
							}
						}
					}
				}
			}
			else
			{
				$user_access = TRUE;
			}
			error_log($dt . "access: " . $sUser . "-" . $user_access . "\n", 3, $pfad . '/debug_saml.log');
			if ($user_access)
			{
				$oUser = $this->api->getUserByName($sUser);
				$debug_export = print_r($oUser, TRUE);
				//error_log($dt . "status: " . $sUser . " - " . $debug_export . "\n", 3, $pfad . '/debug_saml.log');
				if (is_null($oUser))
				{
					// Create user
					// If user is being auto created we set parent ID to 1 (admin user)
					if (isset(Yii::app()->session['loginID']))
					{
						$parentID = Yii::app()->session['loginID'];
					}
					else
					{
						$parentID = 1;
					}
					$auto_create_users = $this->get('auto_create_users', NULL, NULL, TRUE);

					if ($auto_create_users)
					{
						// If user is being auto created we set parent ID to 1 (admin user)
						if (isset(Yii::app()->session['loginID']))
						{
							$parentID = Yii::app()->session['loginID'];
						}
						else
						{
							$parentID = 1;
						}
						$new_pass = createPassword();
						$iNewUID = User::model()->insertUser($sUser, $new_pass, $name, $parentID, $mail);
						if (!$iNewUID)
						{
							$oEvent->set('errorCode', self::ERROR_ALREADY_EXISTING_USER);
							$oEvent->set('errorMessageTitle', '');
							$oEvent->set('errorMessageBody', gT("Failed to add user"));

							return NULL;
						}
						Permission::model()->setGlobalPermission($iNewUID, 'auth_ldap');

						$oEvent->set('newUserID', $iNewUID);
						$oEvent->set('newPassword', $new_pass);
						$oEvent->set('newEmail', $mail);
						$oEvent->set('newFullName', $name);
						$oEvent->set('errorCode', self::ERROR_NONE);

						if ($iNewUID)
						{

							Permission::model()->setGlobalPermission($iNewUID, 'auth_saml');
							Permission::model()->setGlobalPermission($iNewUID, 'surveys', array ('create_p'));

							Permission::model()->insertSomeRecords(array ('uid' => $iNewUID, 'permission' => Yii::app()->getConfig("defaulttemplate"), 'entity_id' => 0, 'entity' => 'template', 'read_p' => 1));

							// Set permissions: Label Sets
							$auto_create_labelsets = $this->get('auto_create_labelsets', NULL, NULL, TRUE);
							if ($auto_create_labelsets)
							{
								Permission::model()->insertSomeRecords(array ('uid' => $iNewUID, 'permission' => 'labelsets', 'entity' => 'global', 'entity_id' => 0, 'create_p' => 1, 'read_p' => 1, 'update_p' => 1, 'delete_p' => 1, 'import_p' => 1, 'export_p' => 1));
							}

							// Set permissions: Particiapnt Panel
							$auto_create_participant_panel = $this->get('auto_create_participant_panel', NULL, NULL, TRUE);
							if ($auto_create_participant_panel)
							{
								Permission::model()->insertSomeRecords(array ('uid' => $iNewUID, 'permission' => 'participantpanel', 'entity' => 'global', 'entity_id' => 0, 'create_p' => 1, 'read_p' => 1, 'update_p' => 1, 'delete_p' => 1, 'export_p' => 1));
							}

							// Set permissions: Settings & Plugins
							$auto_create_settings_plugins = $this->get('auto_create_settings_plugins', NULL, NULL, TRUE);
							if ($auto_create_settings_plugins)
							{
								Permission::model()->insertSomeRecords(array ('uid' => $iNewUID, 'permission' => 'settings', 'entity' => 'global', 'entity_id' => 0, 'create_p' => 0, 'read_p' => 1, 'update_p' => 1, 'delete_p' => 0, 'import_p' => 1, 'export_p' => 0));
							}

							// Set permissions: surveys
							$auto_create_surveys = $this->get('auto_create_surveys', NULL, NULL, TRUE);
							if ($auto_create_surveys)
							{
								Permission::model()->insertSomeRecords(array ('uid' => $iNewUID, 'permission' => 'surveys', 'entity' => 'global', 'entity_id' => 0, 'create_p' => 1, 'read_p' => 1, 'update_p' => 1, 'delete_p' => 1, 'export_p' => 1));
							}

							// Set permissions: Templates
							$auto_create_templates = $this->get('auto_create_templates', NULL, NULL, TRUE);
							if ($auto_create_templates)
							{
								Permission::model()->insertSomeRecords(array ('uid' => $iNewUID, 'permission' => 'templates', 'entity' => 'global', 'entity_id' => 0, 'create_p' => 1, 'read_p' => 1, 'update_p' => 1, 'delete_p' => 1, 'import_p' => 1, 'export_p' => 1));
							}

							// Set permissions: User Groups
							$auto_create_user_groups = $this->get('auto_create_user_groups', NULL, NULL, TRUE);
							if ($auto_create_user_groups)
							{
								Permission::model()->insertSomeRecords(array ('uid' => $iNewUID, 'permission' => 'usergroups', 'entity' => 'global', 'entity_id' => 0, 'create_p' => 1, 'read_p' => 1, 'update_p' => 1, 'delete_p' => 1, 'export_p' => 0));
							}
							$this->setAuthSuccess($oUser);
						}
					}
					else
					{
						$this->setAuthFailure(self::ERROR_USERNAME_INVALID, gT('Credentials are valid but we failed to create a user'));
						error_log($dt . "error: Credentials are valid but we failed to create a user" . "\n", 3, $pfad . '/debug_saml.log');

						return;
					}
				}
				else
				{
					// Update user?
					$auto_update_users = $this->get('auto_update_users', NULL, NULL, TRUE);
					error_log($dt . "update: " . $auto_update_users . "\n", 3, $pfad . '/debug_saml.log');
					if ($auto_update_users)
					{
						$changes = array (
							'full_name' => $name,
							'email'     => $mail,
						);
						User::model()->updateByPk($oUser->uid, $changes);
					}

					if (Permission::model()->hasGlobalPermission('auth_saml', 'read', $oUser->uid))
					{
						error_log($dt . "success: " . $sUser . "\n", 3, $pfad . '/debug_saml.log');
						$this->setAuthSuccess($oUser);
					}
					else
					{
						error_log($dt . "error: Web server authentication method is not allowed for this use" . "\n", 3, $pfad . '/debug_saml.log');
						$this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, gT('Web server authentication method is not allowed for this user'));

						return;
					}
				}
			}
			else
			{
				error_log($dt . "error: You have no access" . "\n", 3, $pfad . '/debug_saml.log');
				$this->setAuthFailure(self::ERROR_UNKNOWN_IDENTITY, 'You have no access');

				return;
			}
		}
	}

	public function getUserName()
	{
		if ($this->_username == NULL)
		{
			$this->ssp = $this->get_saml_instance();
			$attributes = $this->ssp->getAttributes();
			if (!empty($attributes))
			{
				$saml_uid_mapping = $this->get('saml_uid_mapping', NULL, NULL, 'uid');
				if (array_key_exists($saml_uid_mapping, $attributes) && !empty($attributes[$saml_uid_mapping]))
				{
					$username = $attributes[$saml_uid_mapping][0];
					$this->setUsername($username);
				}
			}
		}

		return $this->_username;
	}

	public function getUserCommonName()
	{
		$name = '';

		$this->ssp = $this->get_saml_instance();
		$attributes = $this->ssp->getAttributes();

		if (!empty($attributes))
		{
			$saml_name_mapping = $this->get('saml_name_mapping', NULL, NULL, 'cn');
			if (array_key_exists($saml_name_mapping, $attributes) && !empty($attributes[$saml_name_mapping]))
			{
				$name = $attributes[$saml_name_mapping][0];
			}
		}

		return $name;
	}

	public function getUserMail()
	{
		$mail = '';

		$this->ssp = $this->get_saml_instance();
		$attributes = $this->ssp->getAttributes();
		if (!empty($attributes))
		{
			$saml_mail_mapping = $this->get('saml_mail_mapping', NULL, NULL, 'mail');
			if (array_key_exists($saml_mail_mapping, $attributes) && !empty($attributes[$saml_mail_mapping]))
			{
				$mail = $attributes[$saml_mail_mapping][0];
			}
		}

		return $mail;
	}

	public function getUserGroup()
	{
		$usergroup = '';
		$this->ssp = $this->get_saml_instance();
		$attributes = $this->ssp->getAttributes();
		if (!empty($attributes))
		{
			$saml_group_mapping = $this->get('saml_group_mapping', NULL, NULL, 'memberof');
			if (array_key_exists($saml_group_mapping, $attributes) && !empty($attributes[$saml_group_mapping]))
			{
				$usergroup = $attributes[$saml_group_mapping][0];
			}
		}

		return $usergroup;
	}

	public function afterLogout()
	{

		/*
		 * ToDo: Logout-Funktionalität für SAML muss noch geprüft werden. Gibt Redirect.
		*/
		/*
		$ssp = $this->get_saml_instance();
		$url = Yii::app()->getController()->createUrl('admin/authentication/sa/login');
		$ssp->logout(array (
			             'ReturnTo'         => $url,
			             'ReturnStateParam' => 'LogoutState',
			             'ReturnStateStage' => 'MyLogoutState',
		             ));
		*/
		/*	$ssp = $this->get_saml_instance();
			if ($_REQUEST['LogoutState'])
			{
				$state = SimpleSAML_Auth_State::loadState((string)$_REQUEST['LogoutState'], 'MyLogoutState');
				$ls = $state['saml:sp:LogoutStatus']; // Only works for SAML SP

				if ($ls['Code'] === 'urn:oasis:names:tc:SAML:2.0:status:Success')
				{
					$this->getController()->redirect(array ('/admin/authentication/sa/login'));
				}
			}
		*/
		$ssp = $this->get_saml_instance();
		$redirect = $this->get('logout_redirect', NULL, NULL, '/admin');
		if ($ssp->isAuthenticated())
		{
			Yii::app()->controller->redirect($ssp->getLogoutUrl($redirect));
			Yii::app()->end();
		}
	}


	public function beforeLogout()
	{
		/*
		 * ToDo: Logout-Funktionalität für SAML muss noch geprüft werden. Gibt Redirect.
		*/
		$ssp = $this->get_saml_instance();
		$url = Yii::app()->getController()->createUrl('admin/authentication/sa/login');
		$ssp->logout(array (
			             'ReturnTo'         => $url,
			             'ReturnStateParam' => 'LogoutState',
			             'ReturnStateStage' => 'MyLogoutState',
		             ));
	}

	public function newLoginForm()
	{
		$authtype_base = $this->get('authtype_base', NULL, NULL, 'Authdb');
		$ssp = $this->get_saml_instance();
		$this->getEvent()
			->getContent($authtype_base)
			->addContent('<center>Bitte auf den Button klicken, um die Volkswagen OTLG SSO-Anmeldung zu starten<br>
				<a href="' . $ssp->getLoginURL() . '" title="SAML Login">
				 <img src="' . Yii::app()->baseUrl . '/plugins/AuthSAML/assets/' . 'logo.png"></a></center><br>
				 ', 'prepend');
	}
}