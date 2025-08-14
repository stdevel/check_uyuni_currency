# check_uyuni_currency

`check_uyuni_currency` is a Nagios / Icinga plugin for checking patch currency of hosts managed by Uyuni or SUSE Multi-Linux Manager.

The script checks the patch currency of one or multiple systems. The following information are gathered:

- Outstanding package update counter per category:
  - critical
  - important
  - moderate
  - low
  - enhancement
  - bug fix
- system currency score

To gather these information a valid username / password combination to your management system is required. The login credentials **are prompted** when running the script. To automate this you have two options:

## Setting shell variables

The following shell variables are used:

- `UYUNI_LOGIN` - a username
- `UYUNI_PASSWORD` - the appropriate password

You might also want to set the `HISTFILE` variable (*depending on your shell*) to hide the command including the password in the history:

```command
$ HISTFILE="" UYUNI_LOGIN=mylogin UYUNI_PASSWORD=mypass ./check_uyuni_currency.py -S giertz.stankowic.loc
```

## Using an authfile

A better possibility is to create a authfile with permisions **0600**. Just enter the username in the first line and the password in the second line and hand the path to the script:

```command
$ ./check_uyuni_currency.py -a myauthfile -S giertz.stankowic.loc
```

## Requirements

The plugin requires the `xmlrpclic` module which is shipped with `rhnlib`.
A minimum API version of 1.4 is required - the script checks the API version and aborts if you are using a historic version of Uyuni.

## Usage

By default, the script checks a particular system or multiple systems for outstanding bug fixes and critical updates (*combining critical, important and also moderate patch metrics*). It is possible to control this behaviour by specifying additional parameters (*see below*).
The script also support performance data for data visualization.

The following parameters can be specified:

| Parameter | Description |
|:----------|:------------|
| `-d` / `--debug` | enable debugging outputs (*default: no*) |
| `-h` / `--help` | shows help and quits |
| `-P` / `--show-perfdata` | enables performance data (*default: no*) |
| `-a` / `--authfile` | defines an auth file to use instead of shell variables |
| `-s` / `--server` | defines the server to use (*default: localhost*) |
| `-S` / `--system` | defines one or multiple system(s) to check |
| `-A` / `--all-systems` | checks all registered systems - USE WITH CAUTION (*default: no*) |
| `-t` / `--total-warning` | defines total package update warning threshold (*default: empty*) |
| `-T` / `--total-critical` | defines total package update critical threshold (*default: empty*) |
| `-i` / `--important-warning` | defines security package (*critical, important and moderate security fixes*) update warning threshold (*default: 10*) |
| `-I` / `--important-critical` | defines security package (*critical, important and moderate security fixes*) update warning threshold (*default: 20*) |
| `-b` / `--bugs-warning` | defines bug package update warning threshold (*default: 25*) |
| `-B` / `--bugs-critical` | defines bug package update warning threshold (*default: 50*) |
| `-y` / `--generic-statistics` | checks for inactive and outdated system statistic metrics (*default :no*) |
| `-u` / `--outdated-warning` | defines outdated systems warning percentage threshold (*default: 50*) |
| `-U` / `--outdated-critical` | defines outdated systems critical percentage threshold (*default: 80*) |
| `-n` / `--inactive-warning` | defines inactive systems warning percentage threshold (*default: 10*) |
| `-N` / `--inactive-critical` | defines inactive systems critical percentage threshold (*default: 50*) |
| `--version` | prints programm version and quits |

## Examples

The following example checks a single system on the local Uyuni server:

```command
$ ./check_uyuni_currency.py -S giertz.stankowic.loc
Username: admin
Password:
OK: critical updates okay (0), bug fixes okay (0) for giertz.stankowic.loc
```

Checking multiple systems on a remote Uyuni server, authentication using authfile:

```command
$ ./check_uyuni_currency.py -s st-uyuni02.stankowic.loc -a uyuni.auth -S giertz.stankowic.loc -S shittyrobots.test.loc
OK: giertz.stankowic.loc critical updates okay (0)critical updates okay (0), shittyrobots.test.loc bug fixes okay (0)shittyrobots.test.loc bug fixes okay (0)
```

Checking a single host on a local Uyuni installation, also checking total updates, enabling performance data:

```command
$ ./check_uyuni_currency.py -S giertz.stankowic.loc -t 20 -T 40 -P
Username: admin
Password:
OK: total updates okay (0), critical updates okay (0), bug fixes okay (0) for giertz.stankowic.loc | 'crit_pkgs'=0;10;20;; 'imp_pkgs'=0;10;20;; 'mod_pkgs'=0;10;20;; 'low_pkgs'=0;;;; 'enh_pkgs'=0;;;; 'bug_pkgs'=0;25;50;; 'score'=0;;;;
```

When specifying multiple systems along with performance data, the metric names will get prefix according to the particular host:

```command
$ ./check_uyuni_currency.py -S giertz.stankowic.loc -S shittyrobots.test.loc -a uyuni.auth -P
OK: shittyrobots.test.loc critical updates okay (0)giertz.stankowic.loc critical updates okay (0), shittyrobots.test.loc bug fixes okay (0)giertz.stankowic.loc bug fixes okay (0) | 'shittyrobots.test.loc_crit_pkgs'=0;10;20;; 'shittyrobots.test.loc_imp_pkgs'=0;10;20;; 'shittyrobots.test.loc_mod_pkgs'=0;10;20;; 'shittyrobots.test.loc_low_pkgs'=0;;;; 'shittyrobots.test.loc_enh_pkgs'=0;;;; 'shittyrobots.test.loc_bug_pkgs'=0;25;50;; 'shittyrobots.test.loc_score'=0;;;;'giertz.stankowic.loc_crit_pkgs'=0;10;20;; 'giertz.stankowic.loc_imp_pkgs'=0;10;20;; 'giertz.stankowic.loc_mod_pkgs'=0;10;20;; 'giertz.stankowic.loc_low_pkgs'=0;;;; 'giertz.stankowic.loc_enh_pkgs'=0;;;; 'giertz.stankowic.loc_bug_pkgs'=0;25;50;; 'giertz.stankowic.loc_score'=0;;;;
```

Checking generic statistics of an Uyuni system:

```command
$ ./check_uyuni_currency.py -a uyuni.auth -y -P
OK: outdated systems okay (0), inactive systems okay (0) | 'sys_total'=9;;;; 'sys_outdated'=9;5;8;; 'sys_inact'=0;1;5;;
```
