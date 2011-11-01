<?php
/**
 * Mahara: Electronic portfolio, weblog, resume builder and social networking
 * Copyright (C) 2006-2009 Catalyst IT Ltd and others; see:
 *                         http://wiki.mahara.org/Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @package    mahara
 * @subpackage auth-internal
 * @author     Catalyst IT Ltd
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL
 * @copyright  (C) 2006-2009 Catalyst IT Ltd http://catalyst.net.nz
 *
 */

defined('INTERNAL') || die();
/**
 * @define $docroot '../../'
 */
$docroot = get_config('docroot');
require_once($docroot . 'auth/lib.php');
require_once($docroot . 'lib/institution.php'); // Fails without this. Normally included further down init.php
require_once($docroot . 'auth/casdb/CAS-1.2.1/CAS.php');
require_once($docroot . 'artefact/lib.php');
require_once($docroot . 'artefact/internal/lib.php');

/**
 * This will work with the Drupal CAS server module (or hopefully any other CAS server) to authenticate users
 * with single sign on and single sign off. It will use the Drupal database directly in order to get
 * the details of users who don't yet exist.
 */
class AuthCasdb extends Auth {

    public function __construct($id = null) {
        $this->type                         = 'casdb';
        $this->has_instance_config          = true;

        // TODO proper config stuff needs to be settable
        // For connecting
        $this->config['casversion'] = '2.0';
        $this->config['port'] = 443;
        $this->config['certificate_check'] = false;
        $this->config['proxycas'] = false;
        $this->config['dbtype'] = 'mysql5';

        if (!empty($id)) {
            return $this->init($id);
        }
        return true;
    }

    public function init($id = null) {

        $this->ready = parent::init($id);

        // Check that required fields are set
        if ( empty($this->config['casversion']) ||
             empty($this->config['hostname']) ||
             empty($this->config['port']) ||
             empty($this->config['baseuri']) ) {

            $this->ready = false;
        }

        return $this->ready;

    }

    /**
     * Attempt to authenticate user
     *
     * @param $user
     * @param string $password The password being used for authentication
     * @return bool            True/False based on whether the user
     *                         authenticated successfully
     * @throws AuthUnknownUserException If the user does not exist
     */
    public function authenticate_user_account($user, $password) {

        $this->must_be_ready();

        $this->connectCAS();
        $authenticated = phpCAS::isAuthenticated();
        $casuser = trim(strtolower(phpCAS::getUser()));
        $correctuser = ($casuser == $user->username);
        return ($authenticated && $correctuser);

    }

    /**
     * Imap doesn't export enough information to be able to auto-create users
     * @return bool
     */
    public function can_auto_create_users() {
        return true;
    }

    /**
     * This is where we connect to the Drupal DB directly and get the user info
     *
     * @param string $username
     * @return array
     */
    public function get_user_info($username) {

        if ($this->config['dbtype'] == 'mysql5') {
            $connection = mysql_connect($this->config['dbhost'], $this->config['dbuser'],
                                        $this->config['dbpass'], true);
            if (!$connection) {
                throw new SystemException('Could not connect to external DB host');
            }

            if (!mysql_select_db($this->config['dbname'])) {
                throw new SystemException('Could not switch to external database');
            }

            $useextradata = ( !empty($this->config['dbextraext']) &&
                              !empty($this->config['dbextraint']) &&
                              !empty($this->config['dbextraexttable']) );


            // Use this code if you are using Drupal DB as the user source
            // Drupal has no fields in the user table for real names.
            if ($this->config['usedrupal']) {

                $query = "SELECT f.{$this->config['dbfirstname']} AS firstname,
                                 l.{$this->config['dblastname']}  AS lastname,
                                 u.{$this->config['dbmail']}      AS email ";
                // There will sometimes be extra stuff that Mahara needs from Drupal
                if ($useextradata) {
                    $query .= ", x.{$this->config['dbextraext']} AS {$this->config['dbextraint']} ";
                }
                $query .= " FROM {$this->config['dbtable']} u
                       LEFT JOIN  {$this->config['dbdrupalfirstnametable']} f
                              ON f.entity_id = u.uid
                       LEFT JOIN {$this->config['dbdrupallastnametable']} l
                              ON l.entity_id = u.uid ";
                // There will sometime be extra stuff that Mahara needs from Drupal
                if ($useextradata) {
                    $query .= " LEFT JOIN {$this->config['dbextraexttable']} AS x
                                       ON x.entity_id = u.uid  ";
                }
                $query .= " WHERE {$this->config['dbusername']} = '{$username}'";
            } else {
                // Alternatively, use this code if you are using CiviCRM as the source of user data,
                // with a DB view set up for Moodle and Mahara to read from.
                // First and last name are optional
                $query = "SELECT {$this->config['dbmail']} AS email ";
                $query .= !empty($this->config['dbfirstname']) ? ", {$this->config['dbfirstname']} AS firstname " : '';
                $query .= !empty($this->config['dblastname']) ? ", {$this->config['dblastname']} AS lastname " : '';
                if (!empty($this->config['dbextraext'])) {
                    $query .= ", {$this->config['dbextraext']} ";
                    if (!empty($this->config['dbextraint'])) {
                        $query .= " AS {$this->config['dbextraint']} ";
                    }
                }
                $query .= " FROM {$this->config['dbtable']}
                           WHERE {$this->config['dbusername']} = '{$username}'";

            }

            $result  = mysql_query($query);
            if (!$result) {
                throw new SystemException('Invalid query: ' . mysql_error());
            }
            $numrows = mysql_num_rows($result);

            if ($numrows > 1) {
                // error here. Should only be one user
                throw new SystemException('More than one user found in external DB');
            }

            if ($numrows == 0) {
                // error here. Should only be one user
                throw new SystemException('User not found in external DB. Could also be an SQL error');
            }

            $user = mysql_fetch_array($result);

            mysql_close($connection);

            return $user;
        }

        return false;
    }


    /**
     * When CAS authenticates successfully, we want to keep the service ticket linked to the session so that
     * when a logout request is recieved, we can destroy the session, achieving single sign off
     * @param bool $ticket
     * @return
     */
    public static function store_service_ticket($ticket = false) {

        global $SESSION;

        // this will happen if we are at the later call, when the user has already been authenticated.
        // We assume the ticket is already in the session, but may need to be tied to a newly created userid.
        // This only applies on first ever login.
        if (!$ticket) {
            $ticket = $SESSION->casticket; //retrieve it
        } else {
            $SESSION->casticket = $ticket; // store it
        }

        $username = phpCAS::getUser();
        $userid = get_field('usr', 'id', 'username', $username);

        if (!$userid) {
            // User not created yet
            return;
        }

        $row = new stdClass;
        $row->userid = $userid;
        $row->ticket = $ticket;

        insert_record('auth_casdb', $row);

    }

    /* ------------- Additions - ULCC ------------- */
    /* Robbed from casextended moodle plugin */

    /**
     * Connect to the CAS (clientcas connection or proxycas connection) so that other
     * stuff can be done
     *
     */
    function connectCAS() {
        /**
         * @var CASClient
         */
        global $PHPCAS_CLIENT;

        // Debugging - remove when the site is live or else it'll slow things down
        // phpCAS::setDebug('../../../log/cas_log');

        // Say what time we started
        phpCAS::trace(date('r'));

        if (!is_object($PHPCAS_CLIENT)) {
            // Make sure phpCAS doesn't try to start a new PHP session when connecting to the CAS server.
            if ($this->config['proxycas']) {
                phpCAS::proxy($this->config['casversion'], $this->config['hostname'], (int) $this->config['port'], $this->config['baseuri'], false);
            } else {
                phpCAS::client($this->config['casversion'], $this->config['hostname'], (int) $this->config['port'], $this->config['baseuri'], false);
            }
        }

        // set the single sign out handlers. These work in both directions so it's true single
        // sign off
        phpCAS::setSingleSignoutCallback('PluginAuthCasdb::process_single_sign_off');
        phpCAS::setPostAuthenticateCallback('AuthCasdb::store_service_ticket');

        if($this->config['certificate_check'] && $this->config['certificate_path']){
            phpCAS::setCasServerCACert($this->config['certificate_path']);
        }else{
            // Don't try to validate the server SSL credentials
            phpCAS::setNoCasServerValidation();
        }
    }

    /**
     * Attempts to find the remote username and if successful, either logs in the user or
     * creates an account
     *
     * @global LiveUser $USER
     * @global Session $SESSION
     * @return void
     */
    public function attempt_auth() {

        global $USER, $SESSION;

        // TODO check for whether the institution is suspended
//        if ($this->suspended) {
//            return false;
//        }

        // phpCAS seems to make the headers get sent somehow, so we want to prevent all output till
        // after it's done
        ob_start();

        // Mahara won't start a session until the user gets logged in. We need
        // the session to deal with persistence across the phpCAS redirects, so we do this.
        @session_start();

        $this->connectCAS();

        phpCAS::handleLogoutRequests(false);

        // This redirect will wipe out the $_POST variables
        if (phpCAS::checkAuthentication()) {

            $username = phpCAS::getUser();

            if (!empty($username)) {
                // does user exist already?
                try {
                    // this will find the user with that username and try to use each auth instance
                    // to authenticate. We need to get the authenticate_user_account($user, $password)
                    // to check PHP Cas again and say OK whilst ignoring the password.
                    $authenticated = $USER->login($username, 'dummypassword');
                    if ($authenticated) {
                        // Treat the external system as authoritative and overwrite everything
                        // on each login.
                        $userdata = $this->get_user_info($username);
                        foreach ($userdata as $attribute => $value) {
                            $USER->set($attribute, $value);
                        }
                        $USER->commit();

                        return;
                        //error_log("user account {$username} was found"); // ULCC debug
                    } else {
                        //error_log("user account {$username} was not found"); // ULCC debug
                    }
                }
                catch (AuthUnknownUserException $e) {

                    // If the user doesn't exist, check for institutions that
                    // want to create users automatically.

                    try { // See if we can make a user

                        // Reset the LiveUser object, since we are attempting to create a
                        // new user
                        $SESSION->destroy_session();
                        $USER = new LiveUser();
                        $USER->username = strtolower($username);
                        $USER->password = substr(md5('dummy'.time()), 0, 10);


                        // The normal way this works is that Mahara will cycle through all authentication mechanisms
                        // until it finds one that approves this user. This isn't possible here, as we only have a username
                        // so we either need to assume there is only one institution that can use CAS, or
                        // find a way to get the name of the institution via the cas server. This could
                        // become complex if there is more than one institution on a single CAS server,
                        // or if there are multiple CAS servers to try. Hard coded to one institution for now.

                        $USER->authinstance = $this->instanceid;

                        $institution = new Institution($this->institution);

                        if ($institution->isFull()) {
                            throw new AuthUnknownUserException('Institution has too many users');
                        }

                        try {
                            $userdata = $this->get_user_info($username);
                        } catch (SystemException $e) {
                            $SESSION->add_error_msg('Could not retrieve remote user data for '.$username.': '.$e->getMessage());
                        }

                        if (empty($userdata)) {
                            throw new AuthUnknownUserException("\"$username\" is not known");
                        }

                        // We have the data - create the user
                        $USER->lastlogin = db_format_timestamp(time());

                        if (isset($userdata['firstname'])) {
                            $USER->firstname = $userdata['firstname'];
                        }
                        if (isset($userdata['lastname'])) {
                            $USER->lastname = $userdata['lastname'];
                        }
                        // In case there is anything dynamic
                        if (isset($this->config['dbextraint']) && !empty($this->config['dbextraint'])) {
                            $attribute = $this->config['dbextraint'];
                            if (isset($userdata[$attribute]) && $attribute !== 'studentid') {
                                // For some reason, adding studentid leads to an artefact with owner
                                // of 0, so we do it later.
                                $USER->$attribute = $userdata[$attribute];
                            }
                        }
                        if (isset($userdata['email'])) {
                            $USER->email = $userdata['email'];
                        }
                        else {
                            // The user will be asked to populate this when they log in.
                            $USER->email = null;
                        }

                        // This normally comes as a default from the file artifact, but this seems to
                        // be missing from my dev intall
                        $USER->quota = 52428800;

                        try {
                            create_user($USER, array(), $this->institution, null);
                            $USER->reanimate($USER->id, $this->instanceid);
                            $institution->addUserAsMember($USER);
                            if (isset($userdata['studentid'])) { // bit of a hack :(
                                // Needs storing as an artefact, but only after we have a userid.
                                $profile = new ArtefactTypeStudentid(0, array('owner' => $USER->get('id')));
                                $profile->set('title', $userdata['studentid']);
                                $profile->commit();
                            }
                        }
                        catch (Exception $e) {
                            db_rollback();
                            throw $e;
                        }

                        return; // No exception, so all OK with user creation

                     } catch (AuthUnknownUserException $e) {
                         // No action as probably an anonymous user
                         throw $e;
                         //error_log("user account {$username} was not not created"); // ULCC debug
                     }
                }
            }
        }
        // allow output again now that phpCAS stuff is done
        ob_end_clean();

        // If no authentication happened, we need to redirect to external login if we are not on
        // a public page. Not, however, if this was a direct request for the login page, otherwise
        // admins will be locked out
        $requesturl = $_SERVER['REQUEST_URI'];
        $isloginpage = preg_match('#/?login$#', $requesturl);
        if (defined('PUBLIC') && !$isloginpage) {
            phpCAS::forceAuthentication();
        }

    }

    /**
     * Ensure that a user is logged out of Mahara and the CAS server when a remote system sends a
     * logout request
     *
     * @global type $CFG
     * @global LiveUser $USER
     * @global Session $SESSION
     */
    public function logout() {
        global $USER, $SESSION;

        // logout of mahara
        $USER->logout();
        $SESSION->set('messages', array());

        $this->connectCAS();
        phpCAS::logout();
    }
}

/**
 * Plugin configuration class
 */
class PluginAuthCasdb extends PluginAuth {

    private static $default_config = array(
        'hostname' => '',
        'baseuri' => 'cas_server/',
        'dbhost' => '',
        'dbuser' => '',
        'dbpass' => '',
        'dbname' => '',
        'dbtable' => '',
        'dbmail' => '',
        'dbusername' => '',
        'usedrupal' => 0,
        'dbdrupalfirstnametable' => '',
        'dbfirstname' => '',
        'dbdrupallastnametable' => '',
        'dblastname' => '',
        'dbextraexttable' => '',
        'dbextraext' => '',
        'dbextraint' => ''
    );

    public static function has_config() {
        return false;
    }

    /**
     * CAS auth has to happen before anything else, so at the moment it's simpler to have only one
     * thing that it connects to.
     *
     * @static
     * @return array
     */
    public static function get_config_options() {
        return array();
    }

    public static function has_instance_config() {
        return true;
    }

    public static function is_usable() {
        return true;
    }

    public static function get_instance_config_options($institution, $instance = 0) {

        // Load existing settings
        if ($instance > 0) {
            $default = get_record('auth_instance', 'id', $instance);
            if ($default == false) {
                throw new SystemException('Could not find data for auth instance ' . $instance);
            }
            $current_config = get_records_menu('auth_instance_config', 'instance', $instance, '', 'field, value');

            if ($current_config == false) {
                $current_config = array();
            }

            foreach (self::$default_config as $key => $value) {
                if (array_key_exists($key, $current_config)) {
                    self::$default_config[$key] = $current_config[$key];
                }
            }
        } else {
            $default = new stdClass();
            $default->instancename = get_string('authname', 'auth.casdb');
        }

        $elements = array(
            'instancename' => array(
                'type'  => 'text',
                'title' => get_string('authname', 'auth'),
                'rules' => array(
                    'required' => true,
                ),
                'defaultvalue' => $default->instancename,
            ),
            'instance' => array(
                'type' => 'hidden',
                'value' => $instance
            ),
            'institution' => array(
                'type' => 'hidden',
                'value' => $institution
            ),
            'authname' => array(
                'type' => 'hidden',
                'value' => 'casdb'
            ),
            'hostname' => array(
                'type'  => 'text',
                'title' => get_string('hostname', 'auth.casdb'),
                'rules' => array(
                    'required' => true,
                ),
                'defaultvalue' => self::$default_config['hostname']
            ),
            'baseuri' => array(
                'type'  => 'text',
                'title' => get_string('baseuri', 'auth.casdb'),
                'rules' => array(
                    'required' => true,
                ),
                'defaultvalue' => self::$default_config['baseuri']
            ),
            'dbhost' => array(
                'type'  => 'text',
                'title' => get_string('dbhost', 'auth.casdb'),
                'rules' => array(
                    'required' => true,
                ),
                'defaultvalue' => self::$default_config['dbhost']
            ),
            'dbuser' => array(
                'type'  => 'text',
                'title' => get_string('dbuser', 'auth.casdb'),
                'rules' => array(
                    'required' => true,
                ),
                'defaultvalue' => self::$default_config['dbuser']
            ),
            'dbpass' => array(
                'type'  => 'text',
                'title' => get_string('dbpass', 'auth.casdb'),
                'rules' => array(
                    'required' => true,
                ),
                'defaultvalue' => self::$default_config['dbpass']
            ),
            'dbname' => array(
                'type'  => 'text',
                'title' => get_string('dbname', 'auth.casdb'),
                'rules' => array(
                    'required' => true,
                ),
                'defaultvalue' => self::$default_config['dbname']
            ),
            'dbtable' => array(
                'type'  => 'text',
                'title' => get_string('dbtable', 'auth.casdb'),
                'rules' => array(
                    'required' => true,
                ),
                'defaultvalue' => self::$default_config['dbtable']
            ),
            'dbmail' => array(
                'type'  => 'text',
                'title' => get_string('dbmail', 'auth.casdb'),
                'rules' => array(
                    'required' => true,
                ),
                'defaultvalue' => self::$default_config['dbmail']
            ),
            'dbusername' => array(
                'type'  => 'text',
                'title' => get_string('dbusername', 'auth.casdb'),
                'rules' => array(
                    'required' => true,
                ),
                'defaultvalue' => self::$default_config['dbusername']
            ),
            'dbfirstname' => array(
                'type'  => 'text',
                'title' => get_string('dbfirstname', 'auth.casdb'),
                'rules' => array(
                    'required' => false,
                ),
                'defaultvalue' => self::$default_config['dbfirstname']
            ),
            'dblastname' => array(
                'type'  => 'text',
                'title' => get_string('dblastname', 'auth.casdb'),
                'rules' => array(
                    'required' => false,
                ),
                'defaultvalue' => self::$default_config['dblastname']
            ),
            'dbextraexttable' => array(
                'type'  => 'text',
                'title' => get_string('dbextraexttable', 'auth.casdb'),
                'rules' => array(
                    'required' => false,
                ),
                'defaultvalue' => self::$default_config['dbextraexttable']
            ),
            'dbextraext' => array(
                'type'  => 'text',
                'title' => get_string('dbextraext', 'auth.casdb'),
                'rules' => array(
                    'required' => false,
                ),
                'defaultvalue' => self::$default_config['dbextraext']
            ),
            'dbextraint' => array(
                'type'  => 'text',
                'title' => get_string('dbextraint', 'auth.casdb'),
                'rules' => array(
                    'required' => false,
                ),
                'defaultvalue' => self::$default_config['dbextraint']
            ),
            'usedrupal' => array(
                'type'  => 'checkbox',
                'title' => get_string('usedrupal', 'auth.casdb'),
                'defaultvalue' => self::$default_config['usedrupal'],
            ),
            'dbdrupalfirstnametable' => array(
                'type'  => 'text',
                'title' => get_string('dbdrupalfirstnametable', 'auth.casdb'),
                'rules' => array(
                    'required' => false,
                ),
                'defaultvalue' => self::$default_config['dbdrupalfirstnametable']
            ),
            'dbdrupallastnametable' => array(
                'type'  => 'text',
                'title' => get_string('dbdrupallastnametable', 'auth.casdb'),
                'rules' => array(
                    'required' => false,
                ),
                'defaultvalue' => self::$default_config['dbdrupallastnametable']
            ),

        );

        return array(
            'elements' => $elements,
            'renderer' => 'table'
        );
    }

    public static function save_config_options($values, $form) {

        $authinstance = new stdClass();

        if ($values['instance'] > 0) {
            $values['create'] = false;
            $current = get_records_assoc('auth_instance_config', 'instance', $values['instance'], '', 'field, value');
            $authinstance->id = $values['instance'];
        } else {
            $values['create'] = true;

            // Get the auth instance with the highest priority number (which is
            // the instance with the lowest priority).
            // TODO: rethink 'priority' as a fieldname... it's backwards!!
            $lastinstance = get_records_array('auth_instance', 'institution', $values['institution'], 'priority DESC', '*', '0', '1');

            if ($lastinstance == false) {
                $authinstance->priority = 0;
            } else {
                $authinstance->priority = $lastinstance[0]->priority + 1;
            }
        }

        $authinstance->instancename = $values['instancename'];
        $authinstance->institution  = $values['institution'];
        $authinstance->authname     = $values['authname'];

        if ($values['create']) {
            $values['instance'] = insert_record('auth_instance', $authinstance, 'id', true);
        } else {
            update_record('auth_instance', $authinstance, array('id' => $values['instance']));
        }

        if (empty($current)) {
            $current = array();
        }

        foreach (self::$default_config as $name => $defaultvalue) {

            $record = new stdClass();
            $record->instance = $values['instance'];
            $record->field    = $name;
            $record->value    = empty($values[$name]) ? $defaultvalue : $values[$name];

            if ($values['create'] || !array_key_exists($name, $current)) {
                insert_record('auth_instance_config', $record);
            } else {
                update_record('auth_instance_config', $record, array('instance' => $values['instance'],
                                                                     'field' => $name));
            }
        }

        return $values;

    }


    /**
     * This receives the service ticket that was used to log a user in (sent by Drupal via curl when
     * the user logs out) and searches for sessions that contain it, which are then deleted in order
     * to log the user out of Moodle, achieving single sign off.
     *
     * @param string $ticket
     * @global type $CFG
     * @global type $DB
     * @global type $ADODB_SESS_LIFE
     * @return void
     */
    public static function process_single_sign_off($ticket = '') {

        if (!$ticket) {
            return;
        }

        // TODO - might be more than one?
        $sessionrecord = get_record('auth_casdb', 'ticket', $ticket);

        if (!$sessionrecord) {
            error_log("Could not find session to log off user for ticket {$ticket}");
            return;
        }

        // need to destroy the session so that when the user tries to access a page, it'll fail to validate
        // the sesskey.
        require_once(get_config('docroot') . 'auth/session.php');
        remove_user_sessions($sessionrecord->userid);

        // Remove ticket to avoid the table getting clogged
        delete_records('auth_casdb', 'ticket', $ticket);
    }


}

?>
