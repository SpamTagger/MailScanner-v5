package MailScanner::CustomConfig;

use strict 'vars';
use strict 'refs';
no  strict 'subs'; # Allow bare words for parameter %'s

use vars qw($VERSION);

$VERSION = substr q$Revision: 1.5 $, 10;

my($dbh);
my($sth);
use lib '/usr/spamtagger/lib';
require Email;
require Domain;
require SystemPref;

##################
### SpamWall
##################
sub InitSpamWall {}
sub EndSpamWall {}
sub SpamWall ($message) {
  return getValue('spamwall', $message->{todomain}[0], 1);
}

####################
##### VirusWall
####################
sub InitVirusWall {}
sub EndVirusWall {}
sub VirusWall ($message) {
  return getValue('viruswall', $message->{todomain}[0], 1);
}

####################
##### AllowForms
####################
sub InitAllowForms {}
sub EndAllowForms {}
sub AllowForms ($message) {
  return getValue('allow_forms', $message->{todomain}[0], 0);
}

####################
##### AllowScripts
####################
sub InitAllowScripts {}
sub EndAllowScripts {}
sub AllowScripts ($message) {
  return getValue('allow_scripts', $message->{todomain}[0], 0);
}

####################
##### VirusSubject
####################
sub InitVirusSubject {}
sub EndVirusSubject {}
sub VirusSubject ($message) {
  return getValue('virus_subject', $message->{todomain}[0], '{Virus?}');
}

####################
##### ContentSubject
####################
sub InitContentSubject {}
sub EndContentSubject {}
sub ContentSubject ($message) {
  return getValue('content_subject', $message->{todomain}[0], '{Content?}');
}

##########################
##### StoredContentReport
##########################
sub InitStoredContentReport {}
sub EndStoredContentReport {}
sub StoredContentReport ($message) {
  my $lang = getValue('language', $message->{to}[0], 'en');
  my $ret = getValue('report_template', $message->{todomain}[0], 'default');
  if (-e "/etc/spamtagger/templates/reports/".$ret."/".$lang."/stored.content.message.txt") {
    return "/etc/spamtagger/templates/reports/".$ret."/".$lang."/stored.content.message.txt";
  }
  return "/usr/spamtagger/templates/reports/".$ret."/".$lang."/stored.content.message.txt";
}

##########################
##### StoredFilenameReport
##########################
sub InitStoredFilenameReport {}
sub EndStoredFilenameReport {}
sub StoredFilenameReport ($message) {
  my $lang = getValue('language', $message->{to}[0], 'en');
  my $ret = getValue('report_template', $message->{todomain}[0], 'default');
  if (-e "/etc/spamtagger/templates/reports/".$ret."/".$lang."/stored.filename.message.txt") {
    return "/etc/spamtagger/templates/reports/".$ret."/".$lang."/stored.filename.message.txt";
  }
  return "/usr/spamtagger/templates/reports/".$ret."/".$lang."/stored.filename.message.txt";
}

##########################
##### StoredVirusReport
##########################
sub InitStoredVirusReport {}
sub EndStoredVirusReport {}
sub StoredVirusReport ($message) {
  my $lang = getValue('language', $message->{to}[0], 'en');
  my $ret = getValue('report_template', $message->{todomain}[0], 'default');
  if ( -e "/etc/spamtagger/templates/reports/".$ret."/".$lang."/stored.virus.message.txt") {
    return "/etc/spamtagger/templates/reports/".$ret."/".$lang."/stored.virus.message.txt";
  }
  return "/usr/spamtagger/templates/reports/".$ret."/".$lang."/stored.virus.message.txt";
}

##########################
##### LocalPostmaster
##########################
sub InitLocalPostmaster {}
sub EndLocalPostmaster {}
sub LocalPostmaster ($message) {
  my $postmaster = getValue('supportemail', $message->{todomain}[0], '');
  if ($postmaster eq '' || $postmaster eq 'NOTFOUND') {
    my $sysconf = SystemPref::create();
    return $sysconf->getPref('sysadmin', '') if ( $sysconf);
    return getValue('summary_from', '', '');
  }
  return $postmaster;
}

##########################################
sub getValue ($pref, $to, $default) {
  my $ref;
  my $res = $default;
  my $query = "";

  my $value = $default;
  if ($to =~ /\S+\@\S+/) {
    # user
    my $email = Email::create($to);
    if (! $email) { 
      MailScanner::Log::InfoLog("Couldn't create user: $to");
      return $default;
    }
    $value = $email->getPref($pref, $default);
  } elsif ($to =~ /\S+/) {
    # domain
    my $domain = Domain::create($to);
    if (! $domain) {
      MailScanner::Log::InfoLog("Couldn't create domain: $to");
      return $default;
    }
    $value = $domain->getPref($pref, $default);
  } else {
    # system
    my $sysconf = SystemPref::create();
    if (! $sysconf) {
      MailScanner::Log::InfoLog("Couldn't create system config");
      return $default;
    }
    $value = $sysconf->getPref($pref, $default);
  }
  return $value;
}

##########################################
sub yesNoDisarmValue ($value) {
  return 'convert' if ($value == 2);
  return $value;
}

1;
