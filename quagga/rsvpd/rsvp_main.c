/* Module:   rsvp_main.c
   Contains: RSVP entry point
   Module creator: Vadim Suraev, vadim_suraev@hotmail.com
   */

#include <zebra.h>
#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
#include "vty.h"
#include "log.h"
#include "sigevent.h"
#include "privs.h"
#include "memory.h"

#include "rsvp.h"
#include "rsvp_vty.h"
#include "rsvp_zebra.h"
#include "rsvp_packet.h"

/* rsvpd privileges */
zebra_capabilities_t _caps_p[] = {
  ZCAP_NET_RAW,
  ZCAP_BIND,
  ZCAP_NET_ADMIN,
};

struct zebra_privs_t rsvpd_privs = {
#if defined(QUAGGA_USER) && defined(QUAGGA_GROUP)
  .user = QUAGGA_USER,
  .group = QUAGGA_GROUP,
#endif
#if defined(VTY_GROUP)
  .vty_group = VTY_GROUP,
#endif
  .caps_p = _caps_p,
  .cap_num_p = sizeof (_caps_p) / sizeof (_caps_p[0]),
  .cap_num_i = 0
};

/* Configuration filename and directory. */
char config_default[] = SYSCONFDIR RSVP_DEFAULT_CONFIG;

/* RSVPd options. */
struct option longopts[] = {
  {"daemon", no_argument, NULL, 'd'},
  {"config_file", required_argument, NULL, 'f'},
  {"pid_file", required_argument, NULL, 'i'},
  {"log_mode", no_argument, NULL, 'l'},
  {"dryrun", no_argument, NULL, 'C'},
  {"help", no_argument, NULL, 'h'},
  {"vty_addr", required_argument, NULL, 'A'},
  {"vty_port", required_argument, NULL, 'P'},
  {"user", required_argument, NULL, 'u'},
  {"group", required_argument, NULL, 'g'},
  {"version", no_argument, NULL, 'v'},
  {0}
};

struct thread_master *master;

/* Process ID saved for use by init system */
const char *pid_file = PATH_RSVPD_PID;

/* Help information display. */
static void __attribute__ ((noreturn)) usage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {
      printf ("Usage : %s [OPTION...]\n\
Daemon which manages RSVP.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-i, --pid_file     Set process identifier file name\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
-u, --user         User to run as\n\
-g, --group        Group to run as\n\
-v, --version      Print program version\n\
-C, --dryrun       Check configuration for validity and exit\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);
    }
  exit (status);
}

/* SIGHUP handler. */
static void
sighup (void)
{
  zlog (NULL, LOG_INFO, "SIGHUP received");
}

/* SIGINT / SIGTERM handler. */
static void
sigint (void)
{
  zlog_notice ("Terminating on signal");
}

/* SIGUSR1 handler. */
static void
sigusr1 (void)
{
  zlog_rotate (NULL);
}

struct quagga_signal_t rsvp_signals[] = {
  {
   .signal = SIGHUP,
   .handler = &sighup,
   },
  {
   .signal = SIGUSR1,
   .handler = &sigusr1,
   },
  {
   .signal = SIGINT,
   .handler = &sigint,
   },
  {
   .signal = SIGTERM,
   .handler = &sigint,
   },
};

/* RSVPd main routine. */
int
main (int argc, char **argv)
{
  char *p;
  char *vty_addr = NULL;
  int vty_port = RSVP_VTY_PORT;
  int daemon_mode = 0;
  char *config_file = NULL;
  char *progname;
  struct thread thread;
  int dryrun = 0;

  /* Set umask before anything for security */
  umask (0027);

  /* get program name */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  /* Invoked by a priviledged user? -- endo. */
  if (geteuid () != 0)
    {
      errno = EPERM;
      perror (progname);
      exit (1);
    }

  zlog_default = openzlog (progname, ZLOG_RSVP,
			   LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);

  while (1)
    {
      int opt;

      opt = getopt_long (argc, argv, "dlf:i:hA:P:u:g:vC", longopts, 0);

      if (opt == EOF)
	break;

      switch (opt)
	{
	case 0:
	  break;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'f':
	  config_file = optarg;
	  break;
	case 'A':
	  vty_addr = optarg;
	  break;
	case 'i':
	  pid_file = optarg;
	  break;
	case 'P':
	  /* Deal with atoi() returning 0 on failure, and rsvpd not
	     listening on rsvpd port... */
	  if (strcmp (optarg, "0") == 0)
	    {
	      vty_port = 0;
	      break;
	    }
	  vty_port = atoi (optarg);
	  vty_port = (vty_port ? vty_port : RSVP_VTY_PORT);
	  break;
	case 'u':
	  rsvpd_privs.user = optarg;
	  break;
	case 'g':
	  rsvpd_privs.group = optarg;
	  break;
	case 'v':
	  print_version (progname);
	  exit (0);
	  break;
	case 'C':
	  dryrun = 1;
	  break;
	case 'h':
	  usage (progname, 0);
	  break;
	default:
	  usage (progname, 1);
	  break;
	}
    }

  /* Make master thread emulator. */
  master = thread_master_create ();

  /* Library inits. */
  zprivs_init (&rsvpd_privs);
  signal_init (master, Q_SIGC (rsvp_signals), rsvp_signals);
  cmd_init (1);
  vty_init (master);
  memory_init ();
  rsvp_vty ();

  InitRsvpDecoder ();
  InitRsvpPathMessageProcessing ();
  InitResvProcessing ();
  InitInterfaceIpAdressesDB ();

  if (rdb_create () != E_OK)
    {
      zlog_err ("an error on RDB creation...");
      return 0;
    }
  if (TeApplicationInit () != E_OK)
    zlog_err ("TE application init failed");

  if (InitInterfaceDB () != E_OK)
    zlog_err ("cannot initiate I/F DB");

  rsvp_zebra_init ();
  rsvp_te_comm_init ();

  sort_node ();

  /* Get configuration file. */
  vty_read_config (config_file, config_default);

  /* Start execution only if not in dry-run mode */
  if (dryrun)
    return (0);

  /* Change to the daemon program. */
  if (daemon_mode)
    daemon (0, 0);

  /* Process id file create. */
  pid_output (pid_file);

  /* Create VTY socket */
  vty_serv_sock (vty_addr, vty_port, RSVP_VTYSH_PATH);

  /* Print banner. */
  zlog_notice ("RSVPd %s starting: vty@%d", QUAGGA_VERSION, vty_port);

  /* Fetch next active thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  return (0);
}
