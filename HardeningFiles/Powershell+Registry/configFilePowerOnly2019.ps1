
## *-----------------* CIS Windows 2019 Compliant Firewall Registry *-----------------* 


# Configuration Definition
Configuration CIS_WindowsServer2019_v110 {
   param (
       [string[]]$NodeName ='localhost'
       )


   Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
   Import-DscResource -ModuleName 'AuditPolicyDsc'
   Import-DscResource -ModuleName 'SecurityPolicyDsc'
   Import-DscResource -ModuleName 'AuditPolicySubcategory'

   Node $NodeName {
      AccountPolicy AccountPolicies
        {
            Name                                        = 'PasswordPolicies'
            # 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
            Enforce_password_history                    = 24

            # 1.1.2 (L1)Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'
            Maximum_Password_Age                        = 365

            # 1.1.3 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
            Maximum_Password_Age                        = 60

            # 1.1.4 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'
            Minimum_Password_Age                        = 1

            # 1.1.5 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
            Minimum_Password_Length                     = 14

            # 1.1.6 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'
            Password_must_meet_complexity_requirements  = 'Enabled'

            # 1.1.7 (L1) Ensure 'Relax minimum password length limits' is set to 'Enabled'
            Relax_minimum_Password_length               = 'Enabled'

            # 1.1.8 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
            Store_passwords_using_reversible_encryption = 'Disabled'

            # 1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'
            Account_lockout_duration                    = 15

            # 1.2.2 (L1) Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'
            Account_lockout_threshold                   = 5

            # 1.2.3 (L1) Ensure 'Account lockout threshold' is set to '3 or fewer invalid logon attempt(s), but not 0'
            Account_lockout_threshold                   = 3

            # 1.2.4 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
            Reset_account_lockout_counter_after         = 15
            
            ## Did not add Kerberos Policy because Vagaro does not use it. - #1.3
        }


      # 2.1 Audit Policy - This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

      #  2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
       UserRightsAssignment AccessCredentialManagerasatrustedcaller {
          Policy       = 'Access_Credential_Manager_as_a_trusted_caller'
          Identity     = ''
       }

      #  2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS' (DC only)
       UserRightsAssignment Accessthiscomputerfromthenetwork {
          Policy       = 'Access_this_computer_from_the_network'
          Identity     = 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS'
       }

      #  2.2.3 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users' (MS only)
      # WARNING! Duplicate. Commented out
      #   UserRightsAssignment Accessthiscomputerfromthenetwork {
      #      Policy       = 'Access_this_computer_from_the_network'
      #      Identity     = 'Administrators, Authenticated Users'
      #   }


      #  2.2.4 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
       UserRightsAssignment Actaspartoftheoperatingsystem {
          Policy       = 'Act_as_part_of_the_operating_system'
          Identity     = ''
       }

      #  2.2.5 (L1) Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)
       UserRightsAssignment Addworkstationstodomain {
          Policy       = 'Add_workstations_to_domain'
          Identity     = 'Administrators'
       }

      #  2.2.6 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
      UserRightsAssignment Adjustmemoryquotasforaprocess {
         Policy       = 'Adjust_memory_quotas_for_a_process'
         Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
      }

      #  2.2.7 (L1) Ensure 'Allow log on locally' is set to 'Administrators'
       UserRightsAssignment Allowlogonlocally {
          Policy       = 'Allow_log_on_locally'
          Identity     = 'Administrators'
       }

      #  2.2.8 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators' (DC only)
       UserRightsAssignment AllowlogonthroughRemoteDesktopServices {
          Policy       = 'Allow_log_on_through_Remote_Desktop_Services'
          Identity     = 'Administrators'
       }

      #  2.2.9 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (MS only)
      # WARNING! Duplicate.
      #  UserRightsAssignment AllowlogonthroughRemoteDesktopServices {
      #     Policy       = 'Allow_log_on_through_Remote_Desktop_Services'
      #     Identity     = 'Administrators, Remote Desktop Users'
      #  }

      #  2.2.10 (L1) Ensure 'Back up files and directories' is set to 'Administrators'
       UserRightsAssignment Backupfilesanddirectories {
          Policy       = 'Back_up_files_and_directories'
          Identity     = 'Administrators'
       }

      #  2.2.11 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
       UserRightsAssignment Changethesystemtime {
          Policy       = 'Change_the_system_time'
          Identity     = 'Administrators, LOCAL SERVICE'
       }

      #  2.2.12 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
       UserRightsAssignment Changethetimezone {
          Policy       = 'Change_the_time_zone'
          Identity     = 'Administrators, LOCAL SERVICE'
       }

      #  2.2.13 (L1) Ensure 'Create a pagefile' is set to 'Administrators'
       UserRightsAssignment Createapagefile {
          Policy       = 'Create_a_pagefile'
          Identity     = 'Administrators'
       }

      #  2.2.14 (L1) Ensure 'Create a token object' is set to 'No One'
       UserRightsAssignment Createatokenobject {
          Policy       = 'Create_a_token_object'
          Identity     = ''
       }

      #  2.2.15 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
       UserRightsAssignment Createglobalobjects {
          Policy       = 'Create_global_objects'
          Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
       }

      #  2.2.16 (L1) Ensure 'Create permanent shared objects' is set to 'No One'
       UserRightsAssignment Createpermanentsharedobjects {
          Policy       = 'Create_permanent_shared_objects'
          Identity     = ''
       }

      #  2.2.17 (L1) Ensure 'Create symbolic links' is set to 'Administrators' (DC only)
       UserRightsAssignment Createsymboliclinks {
          Policy       = 'Create_symbolic_links'
          Identity     = 'Administrators'
       }

      #  2.2.18 (L1) Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines' (MS only)
      #  WARNING! Duplicate.
      #  UserRightsAssignment Createsymboliclinks {
      #     Policy       = 'Create_symbolic_links'
      #     Identity     = 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'
      #  }

      #  2.2.19 (L1) Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'
      UserRightsAssignment Createsymboliclinks {
         Policy       = 'Create_symbolic_links'
         Identity     = 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'
      }

      #  2.2.20 (L1) Ensure 'Debug programs' is set to 'Administrators'
       UserRightsAssignment Debugprograms {
          Policy       = 'Debug_programs'
          Identity     = 'Administrators'
       }

      #  2.2.21 (L1) Ensure 'Deny access to this computer from the network' is set to 'Guests' (DC only)
      # WARNING! Duplicate
      #  UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
      #     Policy       = 'Deny_access_to_this_computer_from_the_network'
      #     Identity     = 'Guests'
      #  }

      #  2.2.22 (L1) Ensure 'Deny access to this computer from the network' is set to 'Guests, Local account and member of Administrators group' (MS only)
       UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
          Policy       = 'Deny_access_to_this_computer_from_the_network'
          Identity     = 'Guests, Local account, Administrators'
       }

      #  2.2.23 (L1) Ensure 'Deny access to this computer from the network' to include 'Guests, Enterprise Admins Group, Domains Admins Group, Local account, and member of Administrators group' (STIG MS only)
      UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
         Policy       = 'Deny_access_to_this_computer_from_the_network'
         Identity     = 'Guests, Local account, Administrators, Enterprise Admins Group, Domain Admins Group'
      }

      #  2.2.24 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'
       UserRightsAssignment Denylogonasabatchjob {
          Policy       = 'Deny_log_on_as_a_batch_job'
          Identity     = 'Guests'
       }

      #  2.2.25 (L1) Ensure 'Deny log on as a batch job' to include 'Guests' (STIG DC only)
      UserRightsAssignment Denylogonasabatchjob {
         Policy       = 'Deny_log_on_as_a_batch_job'
         Identity     = 'Guests'
      }

      #  2.2.26 (L1) Ensure 'Deny log on as a batch job' to include 'Guests, Enterprise Admins Group, and Domain Admins Group' (STIG MS only)
      UserRightsAssignment Denylogonasabatchjob {
         Policy       = 'Deny_log_on_as_a_batch_job'
         Identity     = 'Guests, Enterprise Admins Group, Domain Admins Group'
      }

      #  2.2.27 (L1) Ensure 'Deny log on as a service' to include 'Guests'
       UserRightsAssignment Denylogonasaservice {
          Policy       = 'Deny_log_on_as_a_service'
          Identity     = 'Guests'
       }

      #  2.2.28 (L1) Ensure 'Deny log on as a service' to include 'No one' (STIG DC only)
      UserRightsAssignment Denylogonasaservice {
         Policy       = 'Deny_log_on_as_a_service'
         Identity     = 'Guests'
      }
      
      #  2.2.29 (L1) Ensure 'Deny log on as a service' to include 'Enterprise Admins Group and Domain Admins Group' (STIG MS only)
      UserRightsAssignment Denylogonasaservice {
         Policy       = 'Deny_log_on_as_a_service'
         Identity     = 'Enterprise Admins Group, Domain Admins Group'
      }

      #  2.2.30 (L1) Ensure 'Deny log on locally' to include 'Guests'
       UserRightsAssignment Denylogonlocally {
          Policy       = 'Deny_log_on_locally'
          Identity     = 'Guests'
       }

      #  2.2.31 (L1) Ensure 'Deny log on locally' to include 'Guests' (STIG DC only)
      UserRightsAssignment Denylogonlocally {
         Policy       = 'Deny_log_on_locally'
         Identity     = 'Guests'
      }

      #  2.2.32 (L1) Ensure 'Deny log on locally' to include 'Guests, Enterprise Admins group, and Domain Admins group' (STIG MS only)
      UserRightsAssignment Denylogonlocally {
         Policy       = 'Deny_log_on_locally'
         Identity     = 'Guests, Enterprise Admins Group, Domain Admins Group'
      }

      # 2.2.33 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests' (DC only)
       UserRightsAssignment DenylogonthroughRemoteDesktopServices {
          Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
          Identity     = 'Guests'
       }

      #  2.2.34 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account' (MS only)
      #WARNING! Duplicate.
      #  UserRightsAssignment DenylogonthroughRemoteDesktopServices2 {
      #     Policy       = 'Deny_log_on_through_Remote_Desktop_Services2'
      #     Identity     = 'Guests, Local account'
      #  }

      # 2.2.35 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account, Enterprise Admins Group, and Domain Admins Group' (STIG MS only)
      UserRightsAssignment DenylogonthroughRemoteDesktopServices {
         Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
         Identity     = 'Guests, Local Account, Enterprise Admins Group, Domain Admins Group'
      }
       
      #  2.2.36 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators' (DC only)
      # WARNING! Duplicate
      #  UserRightsAssignment Enablecomputeranduseraccountstobetrustedfordelegation {
      #     Policy       = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
      #     Identity     = 'Administrators'
      #  }

      #  2.2.37 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (MS only)
       UserRightsAssignment Enablecomputeranduseraccountstobetrustedfordelegation {
          Policy       = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
          Identity     = ''
       }

      #  2.2.38 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'
       UserRightsAssignment Forceshutdownfromaremotesystem {
          Policy       = 'Force_shutdown_from_a_remote_system'
          Identity     = 'Administrators'
       }

      #  2.2.39 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
       UserRightsAssignment Generatesecurityaudits {
          Policy       = 'Generate_security_audits'
          Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
       }

      #  2.2.40 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (DC only)
       UserRightsAssignment Impersonateaclientafterauthentication {
          Policy       = 'Impersonate_a_client_after_authentication'
          Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
       }

      #  2.2.41 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS' (MS only)
      # WARNING! Duplicate
      #  UserRightsAssignment Impersonateaclientafterauthentication {
      #     Policy       = 'Impersonate_a_client_after_authentication'
      #     Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS'
      #  }
      
      #  2.2.42 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (STIG MS only)
      UserRightsAssignment Impersonateaclientafterauthentication {
         Policy       = 'Impersonate_a_client_after_authentication'
         Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
      }

      #  2.2.43 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators'
       UserRightsAssignment Increaseschedulingpriority {
          Policy       = 'Increase_scheduling_priority'
          Identity     = 'Administrators'
       }

      #  2.2.44 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'
      UserRightsAssignment Increaseschedulingpriority {
         Policy       = 'Increase_scheduling_priority'
         Identity     = 'Administrators, Window Manager\Window Manager Group'
      }

      #  2.2.45 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'
       UserRightsAssignment Loadandunloaddevicedrivers {
          Policy       = 'Load_and_unload_device_drivers'
          Identity     = 'Administrators'
       }

      #  2.2.46 (L1) Ensure 'Lock pages in memory' is set to 'No One'
       UserRightsAssignment Lockpagesinmemory {
          Policy       = 'Lock_pages_in_memory'
          Identity     = ''
       }

      #  2.2.47 (L2) Ensure 'Log on as a batch job' is set to 'Administrators' (DC Only)
       UserRightsAssignment Logonasabatchjob {
          Policy       = 'Log_on_as_a_batch_job'
          Identity     = 'Administrators'
       }

      #  2.2.48 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators' and (when Exchange is running in the environment) `Exchange Servers' (DC only)
      # WARNING! Duplicate
      #  UserRightsAssignment Manageauditingandsecuritylog {
      #     Policy       = 'Manage_auditing_and_security_log'
      #     Identity     = ''Administrators' and (when Exchange is running in the environment) `Exchange Servers''
      #  }

      #  2.2.49 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators' (STIG DC only)
       UserRightsAssignment Manageauditingandsecuritylog {
          Policy       = 'Manage_auditing_and_security_log'
          Identity     = 'Administrators'
       }
      
      #  2.2.50 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only)
      UserRightsAssignment Manageauditingandsecuritylog {
         Policy       = 'Manage_auditing_and_security_log'
         Identity     = 'Administrators'
      }

      #  2.2.51 (L1) Ensure 'Modify an object label' is set to 'No One'
       UserRightsAssignment Modifyanobjectlabel {
          Policy       = 'Modify_an_object_label'
          Identity     = ''
       }

      # 2.2.52 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'
       UserRightsAssignment Modifyfirmwareenvironmentvalues {
          Policy       = 'Modify_firmware_environment_values'
          Identity     = 'Administrators'
       }

      #  2.2.53 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
       UserRightsAssignment Performvolumemaintenancetasks {
          Policy       = 'Perform_volume_maintenance_tasks'
          Identity     = 'Administrators'
       }

      #  2.2.54 (L1) Ensure 'Profile single process' is set to 'Administrators'
       UserRightsAssignment Profilesingleprocess {
          Policy       = 'Profile_single_process'
          Identity     = 'Administrators'
       }

      #  2.2.55 (L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
       UserRightsAssignment Profilesystemperformance {
          Policy       = 'Profile_system_performance'
          Identity     = 'Administrators, NT SERVICE\WdiServiceHost'
       }

      #  2.2.56 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
       UserRightsAssignment Replaceaprocessleveltoken {
          Policy       = 'Replace_a_process_level_token'
          Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
       }

      #  2.2.57 (L1) Ensure 'Restore files and directories' is set to 'Administrators'
       UserRightsAssignment Restorefilesanddirectories {
          Policy       = 'Restore_files_and_directories'
          Identity     = 'Administrators'
       }

      #  2.2.58 (L1) Ensure 'Shut down the system' is set to 'Administrators'
       UserRightsAssignment Shutdownthesystem {
          Policy       = 'Shut_down_the_system'
          Identity     = 'Administrators'
       }

      #  2.2.59 (L1) Ensure 'Synchronize directory service data' is set to 'No One' (DC only)
       UserRightsAssignment Synchronizedirectoryservicedata {
          Policy       = 'Synchronize_directory_service_data'
          Identity     = ''
       }

      #  2.2.60 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'
       UserRightsAssignment Takeownershipoffilesorotherobjects {
          Policy       = 'Take_ownership_of_files_or_other_objects'
          Identity     = 'Administrators'
       }

       SecurityOption AccountSecurityOptions {
         Name                                   = 'AccountSecurityOptions'
         # 2.3.1.1 (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled' (MS only)
         Accounts_Administrator_account_status  = 'Disabled'
         # 2.3.1.2 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
         Accounts_Block_Microsoft_accounts      = 'Users cant add or log on with Microsoft accounts'
         # 2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)
         Accounts_Guest_account_status          = 'Disabled'
         # 2.3.1.4 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'
         Accounts_Guest_account_status          = 'Disabled'         
         # 2.3.1.5 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
         Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
         # 2.3.1.6 (L1) Configure 'Accounts: Rename administrator account'
         Accounts_Rename_administrator_account  = 'User_Adm' # WARNING! Any value different from Administrator
         # 2.3.1.7 (L1) Configure 'Accounts: Rename guest account'
         Accounts_Rename_guest_account          = 'User_Guest' # WARNING! Any value different from Guest


         # 2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
         Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
         # 2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
         Audit_Shut_down_system_immediately_if_unable_to_log_security_audits = 'Disabled'


         # 2.3.3 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.


         # 2.3.4.1 (L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
         Devices_Allowed_to_format_and_eject_removable_media          = 'Administrators'
         # 2.3.4.2 (L1) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
         Devices_Prevent_users_from_installing_printer_drivers        = 'Enabled'


         # 2.3.5.1 (L1) Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only)
         Domain_controller_Allow_server_operators_to_schedule_tasks              = 'Disabled'
         # 2.3.5.2 (L1) Ensure 'Domain controller: Allow vulnerable Netlogon secure channel connections' is set to 'Not Configured' (DC Only) 
         Domain_controller_Allow_vulerable_netlogon_secure_channel_connections   = 'Not Configured'
         # 2.3.5.3 (L1) Ensure 'Domain controller: LDAP server channel binding token requirements' is set to 'Always' (DC Only) 
         Domain_controller_LDAP_server_channel_binding_token_requirements        = 'Always'         
         # 2.3.5.4 (L1) Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing' (DC only) 
         Domain_controller_LDAP_server_signing_requirements                      = 'Require signing'
         # 2.3.5.5 (L1) Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled' (DC only) 
         Domain_controller_Refuse_machine_account_password_changes               = 'Disabled'


         # 2.3.6.1 (L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
         Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always   = 'Enabled' 
         # 2.3.6.2 (L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
         Domain_member_Digitally_encrypt_secure_channel_data_when_possible    = 'Enabled'
         # 2.3.6.3 (L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled' 
         Domain_member_Digitally_sign_secure_channel_data_when_possible       = 'Enabled'
         # 2.3.6.4 (L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
         Domain_member_Disable_machine_account_password_changes               = 'Disabled'
         # 2.3.6.5 (L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
         Domain_member_Maximum_machine_account_password_age                   = '30'
         # 2.3.6.6 (L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
         Domain_member_Require_strong_Windows_2000_or_later_session_key       = 'Enabled'


         # 2.3.7.1 (L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
         Interactive_logon_Do_not_display_last_user_name                      = 'Enabled' 
         # 2.3.7.2 (L1) Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'
         Interactive_logon_Do_not_require_CTRL_ALT_DEL                        = 'Disabled' 
         # 2.3.7.3 (L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
         Interactive_logon_Machine_inactivity_limit                           = '900' 
         # 2.3.7.4 (L1) Configure 'Interactive logon: Message text for users attempting to log on' 
         Interactive_logon_Message_text_for_users_attempting_to_log_on        = 'This computer system is the property of Acme Corporation and is for authorised use by employees and designated contractors only. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use.It is the users responsibility to LOG OFF IMMEDIATELY if you do not agree to the conditions stated in this notice.'
         # 2.3.7.5 (L1) Configure 'Interactive logon: Message title for users attempting to log on'
         #Interactive_logon_Message_title_for_users_attempting_to_log_on = '<Logon Warning>'
         Interactive_logon_Message_title_for_users_attempting_to_log_on       = 'Logon Warning'
         # 2.3.7.6 (L2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)' (MS only) 
         Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
         # 2.3.7.7 (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
         Interactive_logon_Prompt_user_to_change_password_before_expiration   = '14'
         # 2.3.7.8 (L1) Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only)
         Interactive_logon_Require_Domain_Controller_authentication_to_unlock_workstation = 'Enabled'
         # 2.3.7.9 (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or 'Force Logoff'
         Interactive_logon_Smart_card_removal_behavior                        = 'Lock Workstation'          
         # 2.3.7.10 (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
         Interactive_logon_Smart_card_removal_behavior                        = 'Lock Workstation'

         
         # 2.3.8.1 (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled' 
         Microsoft_network_client_Digitally_sign_communications_always                 = 'Enabled'
         # 2.3.8.2 (L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled' 
         Microsoft_network_client_Digitally_sign_communications_if_server_agrees       = 'Enabled'
         # 2.3.8.3 (L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' 
         Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'


         # 2.3.9.1 (L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'
         Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15' 
         # 2.3.9.2 (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled' 
         Microsoft_network_server_Digitally_sign_communications_always                   = 'Enabled'
         # 2.3.9.3 (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled' 
         Microsoft_network_server_Digitally_sign_communications_if_client_agrees         = 'Enabled'
         # 2.3.9.4 (L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
         Microsoft_network_server_Disconnect_clients_when_logon_hours_expire             = 'Enabled' 
         # 2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS only) 
         #Microsoft_network_server_Server_SPN_target_name_validation_level = 'Accept if provided by client'
         Microsoft_network_server_Server_SPN_target_name_validation_level                = 'Required from client'


         # 2.3.10.1 (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
         Network_access_Allow_anonymous_SID_Name_translation                              = 'Disabled' 
         # 2.3.10.2 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only) 
         Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts                = 'Enabled'
         # 2.3.10.3 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only) 
         Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares     = 'Enabled'
         # 2.3.10.4 (L2) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
         Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication = 'Enabled' 
         # 2.3.10.5 (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
         Network_access_Let_Everyone_permissions_apply_to_anonymous_users                 = 'Disabled' 
         # 2.3.10.6 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously' (DC only)
         Network_access_Named_Pipes_that_can_be_accessed_anonymously                      = ''
         # 2.3.10.7 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously' (MS only)
         Network_access_Named_Pipes_that_can_be_accessed_anonymously                      = ''
         # 2.3.10.8 (L1) Configure 'Network access: Remotely accessible registry paths' is configured
         Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, SOFTWARE\Microsoft\Windows NT\CurrentVersion'
         # 2.3.10.9 (L1) Configure 'Network access: Remotely accessible registry paths and sub-paths' 
         # Commented out because of bug in SecurityPolicyDSC Module https://github.com/dsccommunity/SecurityPolicyDSC/issues/83
         Network_access_Remotely_accessible_registry_paths_and_subpaths = 'System\CurrentControlSet\Control\Print\Printers, System\CurrentControlSet\Services\Eventlog, Software\Microsoft\OLAP Server, Software\Microsoft\Windows NT\CurrentVersion\Print, Software\Microsoft\Windows NT\CurrentVersion\Windows, System\CurrentControlSet\Control\ContentIndex, System\CurrentControlSet\Control\Terminal Server, System\CurrentControlSet\Control\Terminal Server\UserConfig, System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration, Software\Microsoft\Windows NT\CurrentVersion\Perflib, System\CurrentControlSet\Services\SysmonLog'
         # 2.3.10.10 (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled' 
         Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares               = 'Enabled' 
         # 2.3.10.11 (L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only) 
         Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM              = 'Administrators: Remote Access: Allow'

         Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = @(
            MSFT_RestrictedRemoteSamSecurityDescriptor
            {
               Permission = 'Allow'
               Identity   = 'Administrators'
            }
            )

         # 2.3.10.12 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' 
         Network_access_Shares_that_can_be_accessed_anonymously = ''
         # 2.3.10.13 (L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves' 
         Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - local users authenticate as themselves'


         # 2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' 
         Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
         # 2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled' 
         Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
         # 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled' 
         Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
         # 2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' 
         Network_security_Configure_encryption_types_allowed_for_Kerberos = 'AES128_HMAC_SHA1','AES256_HMAC_SHA1','FUTURE'
         # 2.3.11.5 (L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled' 
         Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
         # 2.3.11.6 (L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled' 
         Network_security_Force_logoff_when_logon_hours_expire = 'Enabled'
         # 2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
         Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM' 
         # 2.3.11.8 (L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
         Network_security_LDAP_client_signing_requirements = 'Negotiate signing' 
         # 2.3.11.9 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption' 
         Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
         # 2.3.11.10 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption' 
         Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked' 


         # 2.3.12 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.


         # 2.3.13.1 (L1) Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
         Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled' 

         # 2.3.14.1 (L1) Ensure 'System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User must enter a password each time they use a key'
         System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key' 

         # 2.3.14.2 (L1) Ensure 'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' is set to 'Enabled'
         System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled' 

         # 2.3.15.1 (L1) Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
         System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled' 

         # 2.3.15.2 (L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
         System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled' 

         
         # 2.3.16 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.


         # 2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled' 
         User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
         # 2.3.17.2 (L1) Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled' 
         User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
         # 2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' 
         User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
         # 2.3.17.4 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop or Prompt for credentials on the secure desktop'
         User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'         
         # 2.3.17.5 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests' 
         User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
         # 2.3.17.6 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled' 
         User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
         # 2.3.17.7 (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' 
         User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
         # 2.3.17.8 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
         User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
         # 2.3.17.9 (L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled' 
         User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
         # 2.3.17.10 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
         User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'

       }
      

       # 3 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
       # 4 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
       
       
       # 5.1	Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Not Installed'
       Microsoft_FTP_Service_FTPSVC = 'Not Installed'
       # 5.2	Ensure 'Peer Name Resolution Protocol (PNRPsvc)' is set to 'Not Installed'
       Peer_Name_Resolution_Protocol_PNRPsvc = 'Not Installed'
       # 5.3	Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (DC only)
       Print_Spooler_Spooler = 'Disabled'
       # 5.4	Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (MS only)
       Print_Spooler_Spooler = 'Disabled'
       # 5.5	Ensure 'Simple TCP/IP Services (simptcp)' is set to 'Not Installed'
       Simple_TCP/IP_Services_simptcp = 'Not Installed'


       # 6 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
       # 7 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
       # 8 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
       # 9 In registry files.
       # 10 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
       # 11 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
       # 12 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
       # 13 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
       # 14 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
       # 15 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
       # 16 This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

       # 17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'
       AuditPolicySubcategory 'Audit Credential Validation (Success)'
       {
           Name      = 'Credential Validation'
           Ensure    = 'Present'
           AuditFlag = 'Success'
       }

       AuditPolicySubcategory 'Audit Credential Validation (Failure)'
       {
           Name      = 'Credential Validation'
           Ensure    = 'Present'
           AuditFlag = 'Failure'
       }

       # 17.1.2 (L1) 	Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure' (DC Only)
       AuditPolicySubcategory 'Audit Kerberos Authentication Service (Success)'
       {
            Name = 'Kerberos Authentication Service'
            Ensure = 'Present'
            AuditFlag = 'Success'
       }

       AuditPolicySubcategory 'Audit Kerberos Authentication Service (Failure)'
       {
            Name = 'Kerberos Authentication Service'
            Ensure = 'Present'
            AuditFlag = 'Failure'
       }       

       # 17.1.3 (L1) Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure' (DC Only)
       AuditPolicySubcategory 'Audit Kerberos Service Ticket Operations (Success)'
       {
            Name = 'Kerberos Service Ticket Operations'
            Ensure = 'Present'
            AuditFlag = 'Success'
       }

       AuditPolicySubcategory 'Audit Kerberos Service Ticket Operations (Failure)'
       {
            Name = 'Kerberos Service Ticket Operations'
            Ensure = 'Present'
            AuditFlag = 'Failure'
       }

       # 17.2.1 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Application Group Management (Success)'
        {
            Name      = 'Application Group Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Application Group Management (Failure)'
        {
            Name      = 'Application Group Management'    
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        # 17.2.2 (L1) Ensure 'Audit Computer Account Management' is set to include 'Success' (DC only)
        AuditPolicySubcategory 'Audit Computer Account Management (Failure)' 
        {
            Name      = 'Computer Account Management'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'      
         }

         AuditPolicySubcategory 'Audit Computer Account Management (Success)' {
            Name      = 'Computer Account Management'
            Ensure    = 'Present'   
            AuditFlag = 'Success'      
         }

       # 17.2.3 (L1)	Ensure 'Audit Distribution Group Management' is set to include 'Success' (DC only)
       AuditPolicySubcategory 'Audit Distribution Group Management (Failure)' {
         Name      = 'Distribution Group Management'
         Ensure    = 'Absent'
         AuditFlag = 'Failure'
         }

     AuditPolicySubcategory 'Audit Distribution Group Management (Success)' {
         Name      = 'Distribution Group Management'
         Ensure    = 'Present'
         AuditFlag = 'Success'
         }

       # 17.2.4 (L1) Ensure 'Audit Other Account Management Events' is set to include 'Success' (STIG MS only)
       AuditPolicySubcategory 'Audit Other Account Management Events (Failure)' {
         Name      = 'Other Account Management Events'
         Ensure    = 'Absent'
         AuditFlag = 'Failure'
         }

     AuditPolicySubcategory 'Audit Other Account Management Events (Success)' {
         Name      = 'Other Account Management Events'
         Ensure    = 'Present'
         AuditFlag = 'Success'
         }

        # 17.2.5 (L1) Ensure 'Audit Other Account Management Events' is set to include 'Success' (DC only)
        AuditPolicySubcategory 'Audit Security Group Management (Failure)' {
            Name      = 'Security Group Management'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Security Group Management (Success)' {
            Name      = 'Security Group Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        # 17.2.6 (L1) Ensure 'Audit Security Group Management' is set to include 'Success'
        AuditPolicySubcategory 'Audit User Account Management (Failure)' {
            Name      = 'User Account Management'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit User Account Management (Success)' {
            Name      = 'User Account Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        # 17.2.7 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit User Account Management (Failure)' {
            Name      = 'User Account Management'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit User Account Management (Success)' {
            Name      = 'User Account Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        # 17.3.1 (L1) Ensure 'Audit PNP Activity' is set to 'Success' 
        AuditPolicySubcategory 'Audit PNP Activity (Success)' {
            Name      = 'Plug and Play Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit PNP Activity (Failure)' {
            Name      = 'Plug and Play Events'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        # 17.3.2 (L1) Ensure 'Audit Process Creation' is set to 'Success'
        AuditPolicySubcategory 'Audit Process Creation (Success)' {
            Name      = 'Process Creation'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Process Creation (Failure)' {
            Name      = 'Process Creation'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        # 17.4.1 (L1) Ensure 'Audit Directory Service Access' is set to include 'Failure' (DC only)
        AuditPolicySubcategory 'Audit Directory Service Access (Success)' {
            Name      = 'Directory Service Access'
            Ensure    = 'Absent'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Directory Service Access (Failure)' {
            Name      = 'Directory Service Access'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

       # 17.4.2 (L1) Ensure 'Audit Directory Service Access' is set to include 'Success and Failure' (STIG DC only)
        AuditPolicySubcategory 'Audit Directory Service Access (Success)' {
            Name      = 'Directory Service Access'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Directory Service Access (Failure)' {
            Name      = 'Directory Service Access'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        # 17.4.3 (L1) Ensure 'Audit Directory Service Changes' is set to include 'Success' (DC only)
        AuditPolicySubcategory 'Audit Directory Service Changes' {
            Name      = 'Directory Service Changes'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Directory Service Changes (Failure)' {
            Name      = 'Directory Service Changes'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        # 17.4.4 (L1) Ensure 'Audit Directory Service Changes' is set to include 'Success and Failure' (STIG DC only)
        AuditPolicySubcategory 'Audit Directory Service Changes (Success)' {
            Name      = 'Directory Service Changes'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Directory Service Changes (Failure)' {
            Name      = 'Directory Service Changes'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        # 17.5.1 (L1) Ensure 'Audit Account Lockout' is set to 'Failure'
        AuditPolicySubcategory 'Audit Account Lockout (Success)' {
            Name      = 'Account Lockout'
            Ensure    = 'Absent'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Account Lockout (Failure)' {
            Name      = 'Account Lockout'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        # 17.5.2 (L1) Ensure 'Audit Account Lockout' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Account Lockout (Success)' {
            Name      = 'Account Lockout'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Account Lockout (Failure)' {
            Name      = 'Account Lockout'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.5.3 (L1) Ensure 'Audit Group Membership' is set to 'Success'
        AuditPolicySubcategory 'Audit Group Membership (Success)' {
            Name      = 'Group Membership'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Group Membership (Failure)' {
            Name      = 'Group Membership'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
         }
        
        # 17.5.4 (L1) Ensure 'Audit Logoff' is set to 'Success'
        AuditPolicySubcategory 'Audit Logoff (Success)' {
            Name      = 'Logoff'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Logoff (Failure)' {
            Name      = 'Logoff'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.5.5 (L1) Ensure 'Audit Logon' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Logon (Success)' {
            Name      = 'Logon'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Logon (Failure)' {
            Name      = 'Logon'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.5.6 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure)' {
            Name      = 'Other Logon/Logoff Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success)' {
            Name      = 'Other Logon/Logoff Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.5.7 (L1) Ensure 'Audit Special Logon' is set to 'Success'
        AuditPolicySubcategory 'Audit Special Logon (Success)' {
            Name      = 'Special Logon'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Special Logon (Failure)' {
            Name      = 'Special Logon'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.6.1 (L1) Ensure 'Audit Detailed File Share' is set to include 'Failure'
        AuditPolicySubcategory 'Audit Detailed File Share (Success)' {
            Name      = 'Detailed File Share'
            Ensure    = 'Absent'
            AuditFlag = 'Success'
         }

        AuditPolicySubcategory 'Audit Detailed File Share (Failure)' {
            Name      = 'Detailed File Share'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
         }       

        # 17.6.2 (L1) Ensure 'Audit  File Share' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit File Share (Success)' {
            Name      = 'File Share'
            Ensure    = 'Present'
            AuditFlag = 'Success'
         }

        AuditPolicySubcategory 'Audit File Share (Failure)' {
            Name      = 'File Share'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
         }   

        # 17.6.3 (L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other Object Access Events (Success)' {
            Name      = 'Other Object Access Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Other Object Access Events (Failure)' {
            Name      = 'Other Object Access Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.6.4 (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Removable Storage (Success)' {
            Name      = 'Removable Storage'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Removable Storage (Failure)' {
            Name      = 'Removable Storage'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        # 17.7.1 (L1) Ensure 'Audit Audit Policy Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Policy Change (Success)' {
            Name      = 'Audit Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Policy Change (Failure)' {
            Name      = 'Audit Policy Change'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        # 17.7.2 (L1) Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Policy Change (Success)' {
            Name      = 'Audit Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Policy Change (Failure)' {
            Name      = 'Audit Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.7.3 (L1) Ensure 'Audit Authentication Policy Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Authentication Policy Change (Success)' {
            Name      = 'Authentication Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Authentication Policy Change (Failure)' {
            Name      = 'Authentication Policy Change'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }
        
        # 17.7.4 (L1) Ensure 'Audit Authorization Policy Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Authorization Policy Change (Success)' {
            Name      = 'Authorization Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Authorization Policy Change (Failure)' {
            Name      = 'Authorization Policy Change'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        # 17.7.5 (L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success)' {
            Name      = 'MPSSVC Rule-Level Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure)' {
            Name      = 'MPSSVC Rule-Level Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        # 17.7.6 (L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure'
        AuditPolicySubcategory 'Audit Other Policy Change Events (Success)' {
            Name      = 'Other Policy Change Events'
            Ensure    = 'Absent'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Other Policy Change Events (Failure)' {
            Name      = 'Other Policy Change Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        # 17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure)' {
            Name      = 'Sensitive Privilege Use'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success)' {
            Name      = 'Sensitive Privilege Use'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.1 (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit IPsec Driver (Failure)' {
            Name      = 'IPsec Driver'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit IPsec Driver (Success)' {
            Name      = 'IPsec Driver'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.2 (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other System Events (Failure)' {
            Name      = 'Other System Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Other System Events (Success)' {
            Name      = 'Other System Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.3 (L1) Ensure 'Audit Security State Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Security State Change (Success)' {
            Name      = 'Security State Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Security State Change (Failure)' {
            Name      = 'Security State Change'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }
        
        # 17.9.4 (L1) Ensure 'Audit Security System Extension' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Security System Extension (Failure)' {
            Name      = 'Security System Extension'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Security System Extension (Success)' {
            Name      = 'Security System Extension'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.5 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit System Integrity (Failure)' {
            Name      = 'System Integrity'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit System Integrity (Success)' {
            Name      = 'System Integrity'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }


      
      # 18 In registry files.
      # 19 In registry files.

       
      }
}

CIS_WindowsServer2019_v110
