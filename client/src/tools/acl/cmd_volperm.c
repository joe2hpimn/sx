/*
  File autogenerated by gengetopt version 2.22.6
  generated with the following command:
  gengetopt --unamed-opts --no-handle-version --no-handle-error --file-name=cmd_volperm --func-name=volperm_cmdline_parser --arg-struct-name=volperm_args_info

  The developers of gengetopt consider the fixed text that goes in all
  gengetopt output files to be in the public domain:
  we make no copyright claims on it.
*/

/* If we use autoconf.  */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FIX_UNUSED
#define FIX_UNUSED(X) (void) (X) /* avoid warnings for unused params */
#endif

#include <getopt.h>

#include "cmd_volperm.h"

const char *volperm_args_info_purpose = "";

const char *volperm_args_info_usage = "Usage: sxacl volperm [OPTIONS] user sx://[profile@]cluster/volume";

const char *volperm_args_info_versiontext = "";

const char *volperm_args_info_description = "";

const char *volperm_args_info_full_help[] = {
  "  -h, --help                 Print help and exit",
  "      --full-help            Print help, including hidden options, and exit",
  "  -V, --version              Print version and exit",
  "\nVolume permission modification options:",
  "      --grant=<privileges>   Grant a privilege on the volume to the user",
  "      --revoke=<privileges>  Revoke a privilege on the volume from the user",
  "where <privileges> can be a comma-separated list of privileges:\n \"read\", \"write\", or \"manager\"",
  "\nCommon options:",
  "  -c, --config-dir=PATH      Path to SX configuration directory",
  "  -D, --debug                Enable debug messages  (default=off)",
    0
};

static void
init_help_array(void)
{
  volperm_args_info_help[0] = volperm_args_info_full_help[0];
  volperm_args_info_help[1] = volperm_args_info_full_help[1];
  volperm_args_info_help[2] = volperm_args_info_full_help[2];
  volperm_args_info_help[3] = volperm_args_info_full_help[3];
  volperm_args_info_help[4] = volperm_args_info_full_help[4];
  volperm_args_info_help[5] = volperm_args_info_full_help[5];
  volperm_args_info_help[6] = volperm_args_info_full_help[6];
  volperm_args_info_help[7] = volperm_args_info_full_help[7];
  volperm_args_info_help[8] = volperm_args_info_full_help[9];
  volperm_args_info_help[9] = 0; 
  
}

const char *volperm_args_info_help[10];

typedef enum {ARG_NO
  , ARG_FLAG
  , ARG_STRING
} volperm_cmdline_parser_arg_type;

static
void clear_given (struct volperm_args_info *args_info);
static
void clear_args (struct volperm_args_info *args_info);

static int
volperm_cmdline_parser_internal (int argc, char **argv, struct volperm_args_info *args_info,
                        struct volperm_cmdline_parser_params *params, const char *additional_error);


static char *
gengetopt_strdup (const char *s);

static
void clear_given (struct volperm_args_info *args_info)
{
  args_info->help_given = 0 ;
  args_info->full_help_given = 0 ;
  args_info->version_given = 0 ;
  args_info->grant_given = 0 ;
  args_info->revoke_given = 0 ;
  args_info->config_dir_given = 0 ;
  args_info->debug_given = 0 ;
}

static
void clear_args (struct volperm_args_info *args_info)
{
  FIX_UNUSED (args_info);
  args_info->grant_arg = NULL;
  args_info->grant_orig = NULL;
  args_info->revoke_arg = NULL;
  args_info->revoke_orig = NULL;
  args_info->config_dir_arg = NULL;
  args_info->config_dir_orig = NULL;
  args_info->debug_flag = 0;
  
}

static
void init_args_info(struct volperm_args_info *args_info)
{

  init_help_array(); 
  args_info->help_help = volperm_args_info_full_help[0] ;
  args_info->full_help_help = volperm_args_info_full_help[1] ;
  args_info->version_help = volperm_args_info_full_help[2] ;
  args_info->grant_help = volperm_args_info_full_help[4] ;
  args_info->revoke_help = volperm_args_info_full_help[5] ;
  args_info->config_dir_help = volperm_args_info_full_help[8] ;
  args_info->debug_help = volperm_args_info_full_help[9] ;
  
}

void
volperm_cmdline_parser_print_version (void)
{
  printf ("%s %s\n",
     (strlen(VOLPERM_CMDLINE_PARSER_PACKAGE_NAME) ? VOLPERM_CMDLINE_PARSER_PACKAGE_NAME : VOLPERM_CMDLINE_PARSER_PACKAGE),
     VOLPERM_CMDLINE_PARSER_VERSION);

  if (strlen(volperm_args_info_versiontext) > 0)
    printf("\n%s\n", volperm_args_info_versiontext);
}

static void print_help_common(void) {
  volperm_cmdline_parser_print_version ();

  if (strlen(volperm_args_info_purpose) > 0)
    printf("\n%s\n", volperm_args_info_purpose);

  if (strlen(volperm_args_info_usage) > 0)
    printf("\n%s\n", volperm_args_info_usage);

  printf("\n");

  if (strlen(volperm_args_info_description) > 0)
    printf("%s\n\n", volperm_args_info_description);
}

void
volperm_cmdline_parser_print_help (void)
{
  int i = 0;
  print_help_common();
  while (volperm_args_info_help[i])
    printf("%s\n", volperm_args_info_help[i++]);
}

void
volperm_cmdline_parser_print_full_help (void)
{
  int i = 0;
  print_help_common();
  while (volperm_args_info_full_help[i])
    printf("%s\n", volperm_args_info_full_help[i++]);
}

void
volperm_cmdline_parser_init (struct volperm_args_info *args_info)
{
  clear_given (args_info);
  clear_args (args_info);
  init_args_info (args_info);

  args_info->inputs = 0;
  args_info->inputs_num = 0;
}

void
volperm_cmdline_parser_params_init(struct volperm_cmdline_parser_params *params)
{
  if (params)
    { 
      params->override = 0;
      params->initialize = 1;
      params->check_required = 1;
      params->check_ambiguity = 0;
      params->print_errors = 1;
    }
}

struct volperm_cmdline_parser_params *
volperm_cmdline_parser_params_create(void)
{
  struct volperm_cmdline_parser_params *params = 
    (struct volperm_cmdline_parser_params *)malloc(sizeof(struct volperm_cmdline_parser_params));
  volperm_cmdline_parser_params_init(params);  
  return params;
}

static void
free_string_field (char **s)
{
  if (*s)
    {
      free (*s);
      *s = 0;
    }
}


static void
volperm_cmdline_parser_release (struct volperm_args_info *args_info)
{
  unsigned int i;
  free_string_field (&(args_info->grant_arg));
  free_string_field (&(args_info->grant_orig));
  free_string_field (&(args_info->revoke_arg));
  free_string_field (&(args_info->revoke_orig));
  free_string_field (&(args_info->config_dir_arg));
  free_string_field (&(args_info->config_dir_orig));
  
  
  for (i = 0; i < args_info->inputs_num; ++i)
    free (args_info->inputs [i]);

  if (args_info->inputs_num)
    free (args_info->inputs);

  clear_given (args_info);
}


static void
write_into_file(FILE *outfile, const char *opt, const char *arg, const char *values[])
{
  FIX_UNUSED (values);
  if (arg) {
    fprintf(outfile, "%s=\"%s\"\n", opt, arg);
  } else {
    fprintf(outfile, "%s\n", opt);
  }
}


int
volperm_cmdline_parser_dump(FILE *outfile, struct volperm_args_info *args_info)
{
  int i = 0;

  if (!outfile)
    {
      fprintf (stderr, "%s: cannot dump options to stream\n", VOLPERM_CMDLINE_PARSER_PACKAGE);
      return EXIT_FAILURE;
    }

  if (args_info->help_given)
    write_into_file(outfile, "help", 0, 0 );
  if (args_info->full_help_given)
    write_into_file(outfile, "full-help", 0, 0 );
  if (args_info->version_given)
    write_into_file(outfile, "version", 0, 0 );
  if (args_info->grant_given)
    write_into_file(outfile, "grant", args_info->grant_orig, 0);
  if (args_info->revoke_given)
    write_into_file(outfile, "revoke", args_info->revoke_orig, 0);
  if (args_info->config_dir_given)
    write_into_file(outfile, "config-dir", args_info->config_dir_orig, 0);
  if (args_info->debug_given)
    write_into_file(outfile, "debug", 0, 0 );
  

  i = EXIT_SUCCESS;
  return i;
}

int
volperm_cmdline_parser_file_save(const char *filename, struct volperm_args_info *args_info)
{
  FILE *outfile;
  int i = 0;

  outfile = fopen(filename, "w");

  if (!outfile)
    {
      fprintf (stderr, "%s: cannot open file for writing: %s\n", VOLPERM_CMDLINE_PARSER_PACKAGE, filename);
      return EXIT_FAILURE;
    }

  i = volperm_cmdline_parser_dump(outfile, args_info);
  fclose (outfile);

  return i;
}

void
volperm_cmdline_parser_free (struct volperm_args_info *args_info)
{
  volperm_cmdline_parser_release (args_info);
}

/** @brief replacement of strdup, which is not standard */
char *
gengetopt_strdup (const char *s)
{
  char *result = 0;
  if (!s)
    return result;

  result = (char*)malloc(strlen(s) + 1);
  if (result == (char*)0)
    return (char*)0;
  strcpy(result, s);
  return result;
}

int
volperm_cmdline_parser (int argc, char **argv, struct volperm_args_info *args_info)
{
  return volperm_cmdline_parser2 (argc, argv, args_info, 0, 1, 1);
}

int
volperm_cmdline_parser_ext (int argc, char **argv, struct volperm_args_info *args_info,
                   struct volperm_cmdline_parser_params *params)
{
  int result;
  result = volperm_cmdline_parser_internal (argc, argv, args_info, params, 0);

  return result;
}

int
volperm_cmdline_parser2 (int argc, char **argv, struct volperm_args_info *args_info, int override, int initialize, int check_required)
{
  int result;
  struct volperm_cmdline_parser_params params;
  
  params.override = override;
  params.initialize = initialize;
  params.check_required = check_required;
  params.check_ambiguity = 0;
  params.print_errors = 1;

  result = volperm_cmdline_parser_internal (argc, argv, args_info, &params, 0);

  return result;
}

int
volperm_cmdline_parser_required (struct volperm_args_info *args_info, const char *prog_name)
{
  FIX_UNUSED (args_info);
  FIX_UNUSED (prog_name);
  return EXIT_SUCCESS;
}


static char *package_name = 0;

/**
 * @brief updates an option
 * @param field the generic pointer to the field to update
 * @param orig_field the pointer to the orig field
 * @param field_given the pointer to the number of occurrence of this option
 * @param prev_given the pointer to the number of occurrence already seen
 * @param value the argument for this option (if null no arg was specified)
 * @param possible_values the possible values for this option (if specified)
 * @param default_value the default value (in case the option only accepts fixed values)
 * @param arg_type the type of this option
 * @param check_ambiguity @see volperm_cmdline_parser_params.check_ambiguity
 * @param override @see volperm_cmdline_parser_params.override
 * @param no_free whether to free a possible previous value
 * @param multiple_option whether this is a multiple option
 * @param long_opt the corresponding long option
 * @param short_opt the corresponding short option (or '-' if none)
 * @param additional_error possible further error specification
 */
static
int update_arg(void *field, char **orig_field,
               unsigned int *field_given, unsigned int *prev_given, 
               char *value, const char *possible_values[],
               const char *default_value,
               volperm_cmdline_parser_arg_type arg_type,
               int check_ambiguity, int override,
               int no_free, int multiple_option,
               const char *long_opt, char short_opt,
               const char *additional_error)
{
  char *stop_char = 0;
  const char *val = value;
  int found;
  char **string_field;
  FIX_UNUSED (field);

  stop_char = 0;
  found = 0;

  if (!multiple_option && prev_given && (*prev_given || (check_ambiguity && *field_given)))
    {
      if (short_opt != '-')
        fprintf (stderr, "%s: `--%s' (`-%c') option given more than once%s\n", 
               package_name, long_opt, short_opt,
               (additional_error ? additional_error : ""));
      else
        fprintf (stderr, "%s: `--%s' option given more than once%s\n", 
               package_name, long_opt,
               (additional_error ? additional_error : ""));
      return 1; /* failure */
    }

  FIX_UNUSED (default_value);
    
  if (field_given && *field_given && ! override)
    return 0;
  if (prev_given)
    (*prev_given)++;
  if (field_given)
    (*field_given)++;
  if (possible_values)
    val = possible_values[found];

  switch(arg_type) {
  case ARG_FLAG:
    *((int *)field) = !*((int *)field);
    break;
  case ARG_STRING:
    if (val) {
      string_field = (char **)field;
      if (!no_free && *string_field)
        free (*string_field); /* free previous string */
      *string_field = gengetopt_strdup (val);
    }
    break;
  default:
    break;
  };


  /* store the original value */
  switch(arg_type) {
  case ARG_NO:
  case ARG_FLAG:
    break;
  default:
    if (value && orig_field) {
      if (no_free) {
        *orig_field = value;
      } else {
        if (*orig_field)
          free (*orig_field); /* free previous string */
        *orig_field = gengetopt_strdup (value);
      }
    }
  };

  return 0; /* OK */
}


int
volperm_cmdline_parser_internal (
  int argc, char **argv, struct volperm_args_info *args_info,
                        struct volperm_cmdline_parser_params *params, const char *additional_error)
{
  int c;	/* Character of the parsed option.  */

  int error_occurred = 0;
  struct volperm_args_info local_args_info;
  
  int override;
  int initialize;
  int check_required;
  int check_ambiguity;
  
  package_name = argv[0];
  
  override = params->override;
  initialize = params->initialize;
  check_required = params->check_required;
  check_ambiguity = params->check_ambiguity;

  if (initialize)
    volperm_cmdline_parser_init (args_info);

  volperm_cmdline_parser_init (&local_args_info);

  optarg = 0;
  optind = 0;
  opterr = params->print_errors;
  optopt = '?';

  while (1)
    {
      int option_index = 0;

      static struct option long_options[] = {
        { "help",	0, NULL, 'h' },
        { "full-help",	0, NULL, 0 },
        { "version",	0, NULL, 'V' },
        { "grant",	1, NULL, 0 },
        { "revoke",	1, NULL, 0 },
        { "config-dir",	1, NULL, 'c' },
        { "debug",	0, NULL, 'D' },
        { 0,  0, 0, 0 }
      };

      c = getopt_long (argc, argv, "hVc:D", long_options, &option_index);

      if (c == -1) break;	/* Exit from `while (1)' loop.  */

      switch (c)
        {
        case 'h':	/* Print help and exit.  */
          volperm_cmdline_parser_print_help ();
          volperm_cmdline_parser_free (&local_args_info);
          exit (EXIT_SUCCESS);

        case 'V':	/* Print version and exit.  */
        
        
          if (update_arg( 0 , 
               0 , &(args_info->version_given),
              &(local_args_info.version_given), optarg, 0, 0, ARG_NO,
              check_ambiguity, override, 0, 0,
              "version", 'V',
              additional_error))
            goto failure;
          volperm_cmdline_parser_free (&local_args_info);
          return 0;
        
          break;
        case 'c':	/* Path to SX configuration directory.  */
        
        
          if (update_arg( (void *)&(args_info->config_dir_arg), 
               &(args_info->config_dir_orig), &(args_info->config_dir_given),
              &(local_args_info.config_dir_given), optarg, 0, 0, ARG_STRING,
              check_ambiguity, override, 0, 0,
              "config-dir", 'c',
              additional_error))
            goto failure;
        
          break;
        case 'D':	/* Enable debug messages.  */
        
        
          if (update_arg((void *)&(args_info->debug_flag), 0, &(args_info->debug_given),
              &(local_args_info.debug_given), optarg, 0, 0, ARG_FLAG,
              check_ambiguity, override, 1, 0, "debug", 'D',
              additional_error))
            goto failure;
        
          break;

        case 0:	/* Long option with no short option */
          if (strcmp (long_options[option_index].name, "full-help") == 0) {
            volperm_cmdline_parser_print_full_help ();
            volperm_cmdline_parser_free (&local_args_info);
            exit (EXIT_SUCCESS);
          }

          /* Grant a privilege on the volume to the user.  */
          if (strcmp (long_options[option_index].name, "grant") == 0)
          {
          
          
            if (update_arg( (void *)&(args_info->grant_arg), 
                 &(args_info->grant_orig), &(args_info->grant_given),
                &(local_args_info.grant_given), optarg, 0, 0, ARG_STRING,
                check_ambiguity, override, 0, 0,
                "grant", '-',
                additional_error))
              goto failure;
          
          }
          /* Revoke a privilege on the volume from the user.  */
          else if (strcmp (long_options[option_index].name, "revoke") == 0)
          {
          
          
            if (update_arg( (void *)&(args_info->revoke_arg), 
                 &(args_info->revoke_orig), &(args_info->revoke_given),
                &(local_args_info.revoke_given), optarg, 0, 0, ARG_STRING,
                check_ambiguity, override, 0, 0,
                "revoke", '-',
                additional_error))
              goto failure;
          
          }
          
          break;
        case '?':	/* Invalid option.  */
          /* `getopt_long' already printed an error message.  */
          goto failure;

        default:	/* bug: option not considered.  */
          fprintf (stderr, "%s: option unknown: %c%s\n", VOLPERM_CMDLINE_PARSER_PACKAGE, c, (additional_error ? additional_error : ""));
          abort ();
        } /* switch */
    } /* while */




  volperm_cmdline_parser_release (&local_args_info);

  if ( error_occurred )
    return (EXIT_FAILURE);

  if (optind < argc)
    {
      int i = 0 ;
      int found_prog_name = 0;
      /* whether program name, i.e., argv[0], is in the remaining args
         (this may happen with some implementations of getopt,
          but surely not with the one included by gengetopt) */

      i = optind;
      while (i < argc)
        if (argv[i++] == argv[0]) {
          found_prog_name = 1;
          break;
        }
      i = 0;

      args_info->inputs_num = argc - optind - found_prog_name;
      args_info->inputs =
        (char **)(malloc ((args_info->inputs_num)*sizeof(char *))) ;
      while (optind < argc)
        if (argv[optind++] != argv[0])
          args_info->inputs[ i++ ] = gengetopt_strdup (argv[optind-1]) ;
    }

  return 0;

failure:
  
  volperm_cmdline_parser_release (&local_args_info);
  return (EXIT_FAILURE);
}
