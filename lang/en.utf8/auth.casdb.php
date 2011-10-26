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
 * @subpackage auth-imap
 * @author     Catalyst IT Ltd
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL
 * @copyright  (C) 2006-2009 Catalyst IT Ltd http://catalyst.net.nz
 *
 */

defined('INTERNAL') || die();

$string['title'] = 'CAS DB';
$string['description'] = 'SSO via CAS falling back to direct database access e.g. to Drupal\'s CAS server module';
$string['notusable'] = 'Uh-oh. Something\'s not right.';
$string['dbhost'] = 'Hostname';
$string['dbuser'] = 'Database user';
$string['dbpass'] = 'Database password';
$string['dbname'] = 'Database name';
$string['dbtable'] = 'Database table';
$string['authname'] = 'CAS Single Sign On';
$string['hostname'] = 'Hostname of CAS server';
$string['baseuri'] = 'Base URI of CAS server (the bit after \'domainname.co.uk/\')';
$string['dbusername'] = 'Database username field';
$string['dbfirstname'] = 'Database firstname field';
$string['dblastname'] = 'Database lastname field';
$string['dbextra1inttable'] = 'Internal Mahara database table to put the first bit of extra data into';
$string['dbextra1int'] = 'Internal Mahara database field to add 1st extra bit of data to';
$string['dbextra1ext'] = 'External database field to get the first bit of extra data from';
$string['dbmail'] = 'Database email field';
$string['dbdrupalfirstnametable'] = 'Table where Drupal keeps firstname';
$string['dbdrupallastnametable'] = 'Table where Drupal keeps last name';
$string['usedrupal'] = 'Use separate Drupal table joins to get user first and last names (table names not needed if not)';




?>
