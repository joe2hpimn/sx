/*
  File autogenerated by gengetopt version 2.22.6
  generated with the following command:
  gengetopt --no-handle-version --no-handle-error --file-name=cmd_main --func-name=main_cmdline_parser --arg-struct-name=main_args_info

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

#include "cmd_main.h"

const char *main_args_info_purpose = "sxreport is used to collect configuration and error information from SX nodes";

const char *main_args_info_usage = "Usage: sxreport [OPTIONS]";

const char *main_args_info_versiontext = "";

const char *main_args_info_description = "";

const char *main_args_info_full_help[] = {
  "  -h, --help             Print help and exit",
  "      --full-help        Print help, including hidden options, and exit",
  "  -V, --version          Print version and exit",
  "      --all              Print all the information below",
  "      --anonymize        Anonymize IP addresses, URLs, and cluster usernames\n                           (default=off)",
  "      --find-request-id  Print all messages corresponding to specified request\n                           ID",
  "      --sysconfdir=PATH  Path to /etc",
  "  -o, --output=STRING    Save output to given file (default:\n                           sxreport-server-<timestamp>.log)",
  "      --append=STRING    Append information from specified file (- is stdin),\n                           anonymized only if --anonymize is specified",
  "\n--all options:\n",
  "      --info             Print static configuration only",
  "      --logs             Print error messages from logs only (NOT anonymized)",
  "      --cluster          Print information about cluster's status & health",
  "      --storage          Print information about the node's local storage",
  "\nCalling sxreport without any options is equivalent to: sxreport --all\n--anonymize. The output is thus suitable for submission in a bugreport or\npublic mailing list discussions.\nIf you want just specific information use the other flags: they are not\nanonymized by default though.\nIf you want to append more information:\nsxreport --append=/path/to/file --anonymize >>sxreport.log",
    0
};

static void
init_help_array(void)
{
  main_args_info_help[0] = main_args_info_full_help[0];
  main_args_info_help[1] = main_args_info_full_help[1];
  main_args_info_help[2] = main_args_info_full_help[2];
  main_args_info_help[3] = main_args_info_full_help[3];
  main_args_info_help[4] = main_args_info_full_help[4];
  main_args_info_help[5] = main_args_info_full_help[5];
  main_args_info_help[6] = main_args_info_full_help[7];
  main_args_info_help[7] = main_args_info_full_help[8];
  main_args_info_help[8] = main_args_info_full_help[9];
  main_args_info_help[9] = main_args_info_full_help[10];
  main_args_info_help[10] = main_args_info_full_help[11];
  main_args_info_help[11] = main_args_info_full_help[12];
  main_args_info_help[12] = main_args_info_full_help[13];
  main_args_info_help[13] = main_args_info_full_help[14];
  main_args_info_help[14] = 0; 
  
}

const char *main_args_info_help[15];

typedef enum {ARG_NO
  , ARG_FLAG
  , ARG_STRING
} main_cmdline_parser_arg_type;

static
void clear_given (struct main_args_info *args_info);
static
void clear_args (struct main_args_info *args_info);

static int
main_cmdline_parser_internal (int argc, char **argv, struct main_args_info *args_info,
                        struct main_cmdline_parser_params *params, const char *additional_error);

static int
main_cmdline_parser_required2 (struct main_args_info *args_info, const char *prog_name, const char *additional_error);

static char *
gengetopt_strdup (const char *s);

static
void clear_given (struct main_args_info *args_info)
{
  args_info->help_given = 0 ;
  args_info->full_help_given = 0 ;
  args_info->version_given = 0 ;
  args_info->all_given = 0 ;
  args_info->anonymize_given = 0 ;
  args_info->find_request_id_given = 0 ;
  args_info->sysconfdir_given = 0 ;
  args_info->output_given = 0 ;
  args_info->append_given = 0 ;
  args_info->info_given = 0 ;
  args_info->logs_given = 0 ;
  args_info->cluster_given = 0 ;
  args_info->storage_given = 0 ;
}

static
void clear_args (struct main_args_info *args_info)
{
  FIX_UNUSED (args_info);
  args_info->anonymize_flag = 0;
  args_info->sysconfdir_arg = NULL;
  args_info->sysconfdir_orig = NULL;
  args_info->output_arg = NULL;
  args_info->output_orig = NULL;
  args_info->append_arg = NULL;
  args_info->append_orig = NULL;
  
}

static
void init_args_info(struct main_args_info *args_info)
{

  init_help_array(); 
  args_info->help_help = main_args_info_full_help[0] ;
  args_info->full_help_help = main_args_info_full_help[1] ;
  args_info->version_help = main_args_info_full_help[2] ;
  args_info->all_help = main_args_info_full_help[3] ;
  args_info->anonymize_help = main_args_info_full_help[4] ;
  args_info->find_request_id_help = main_args_info_full_help[5] ;
  args_info->sysconfdir_help = main_args_info_full_help[6] ;
  args_info->output_help = main_args_info_full_help[7] ;
  args_info->append_help = main_args_info_full_help[8] ;
  args_info->append_min = 0;
  args_info->append_max = 0;
  args_info->info_help = main_args_info_full_help[10] ;
  args_info->logs_help = main_args_info_full_help[11] ;
  args_info->cluster_help = main_args_info_full_help[12] ;
  args_info->storage_help = main_args_info_full_help[13] ;
  
}

void
main_cmdline_parser_print_version (void)
{
  printf ("%s %s\n",
     (strlen(MAIN_CMDLINE_PARSER_PACKAGE_NAME) ? MAIN_CMDLINE_PARSER_PACKAGE_NAME : MAIN_CMDLINE_PARSER_PACKAGE),
     MAIN_CMDLINE_PARSER_VERSION);

  if (strlen(main_args_info_versiontext) > 0)
    printf("\n%s\n", main_args_info_versiontext);
}

static void print_help_common(void) {
  main_cmdline_parser_print_version ();

  if (strlen(main_args_info_purpose) > 0)
    printf("\n%s\n", main_args_info_purpose);

  if (strlen(main_args_info_usage) > 0)
    printf("\n%s\n", main_args_info_usage);

  printf("\n");

  if (strlen(main_args_info_description) > 0)
    printf("%s\n\n", main_args_info_description);
}

void
main_cmdline_parser_print_help (void)
{
  int i = 0;
  print_help_common();
  while (main_args_info_help[i])
    printf("%s\n", main_args_info_help[i++]);
}

void
main_cmdline_parser_print_full_help (void)
{
  int i = 0;
  print_help_common();
  while (main_args_info_full_help[i])
    printf("%s\n", main_args_info_full_help[i++]);
}

void
main_cmdline_parser_init (struct main_args_info *args_info)
{
  clear_given (args_info);
  clear_args (args_info);
  init_args_info (args_info);
}

void
main_cmdline_parser_params_init(struct main_cmdline_parser_params *params)
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

struct main_cmdline_parser_params *
main_cmdline_parser_params_create(void)
{
  struct main_cmdline_parser_params *params = 
    (struct main_cmdline_parser_params *)malloc(sizeof(struct main_cmdline_parser_params));
  main_cmdline_parser_params_init(params);  
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

/** @brief generic value variable */
union generic_value {
    char *string_arg;
    const char *default_string_arg;
};

/** @brief holds temporary values for multiple options */
struct generic_list
{
  union generic_value arg;
  char *orig;
  struct generic_list *next;
};

/**
 * @brief add a node at the head of the list 
 */
static void add_node(struct generic_list **list) {
  struct generic_list *new_node = (struct generic_list *) malloc (sizeof (struct generic_list));
  new_node->next = *list;
  *list = new_node;
  new_node->arg.string_arg = 0;
  new_node->orig = 0;
}


static void
free_multiple_string_field(unsigned int len, char ***arg, char ***orig)
{
  unsigned int i;
  if (*arg) {
    for (i = 0; i < len; ++i)
      {
        free_string_field(&((*arg)[i]));
        free_string_field(&((*orig)[i]));
      }
    free_string_field(&((*arg)[0])); /* free default string */

    free (*arg);
    *arg = 0;
    free (*orig);
    *orig = 0;
  }
}

static void
main_cmdline_parser_release (struct main_args_info *args_info)
{

  free_string_field (&(args_info->sysconfdir_arg));
  free_string_field (&(args_info->sysconfdir_orig));
  free_string_field (&(args_info->output_arg));
  free_string_field (&(args_info->output_orig));
  free_multiple_string_field (args_info->append_given, &(args_info->append_arg), &(args_info->append_orig));
  
  

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

static void
write_multiple_into_file(FILE *outfile, int len, const char *opt, char **arg, const char *values[])
{
  int i;
  
  for (i = 0; i < len; ++i)
    write_into_file(outfile, opt, (arg ? arg[i] : 0), values);
}

int
main_cmdline_parser_dump(FILE *outfile, struct main_args_info *args_info)
{
  int i = 0;

  if (!outfile)
    {
      fprintf (stderr, "%s: cannot dump options to stream\n", MAIN_CMDLINE_PARSER_PACKAGE);
      return EXIT_FAILURE;
    }

  if (args_info->help_given)
    write_into_file(outfile, "help", 0, 0 );
  if (args_info->full_help_given)
    write_into_file(outfile, "full-help", 0, 0 );
  if (args_info->version_given)
    write_into_file(outfile, "version", 0, 0 );
  if (args_info->all_given)
    write_into_file(outfile, "all", 0, 0 );
  if (args_info->anonymize_given)
    write_into_file(outfile, "anonymize", 0, 0 );
  if (args_info->find_request_id_given)
    write_into_file(outfile, "find-request-id", 0, 0 );
  if (args_info->sysconfdir_given)
    write_into_file(outfile, "sysconfdir", args_info->sysconfdir_orig, 0);
  if (args_info->output_given)
    write_into_file(outfile, "output", args_info->output_orig, 0);
  write_multiple_into_file(outfile, args_info->append_given, "append", args_info->append_orig, 0);
  if (args_info->info_given)
    write_into_file(outfile, "info", 0, 0 );
  if (args_info->logs_given)
    write_into_file(outfile, "logs", 0, 0 );
  if (args_info->cluster_given)
    write_into_file(outfile, "cluster", 0, 0 );
  if (args_info->storage_given)
    write_into_file(outfile, "storage", 0, 0 );
  

  i = EXIT_SUCCESS;
  return i;
}

int
main_cmdline_parser_file_save(const char *filename, struct main_args_info *args_info)
{
  FILE *outfile;
  int i = 0;

  outfile = fopen(filename, "w");

  if (!outfile)
    {
      fprintf (stderr, "%s: cannot open file for writing: %s\n", MAIN_CMDLINE_PARSER_PACKAGE, filename);
      return EXIT_FAILURE;
    }

  i = main_cmdline_parser_dump(outfile, args_info);
  fclose (outfile);

  return i;
}

void
main_cmdline_parser_free (struct main_args_info *args_info)
{
  main_cmdline_parser_release (args_info);
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

static char *
get_multiple_arg_token(const char *arg)
{
  const char *tok;
  char *ret;
  size_t len, num_of_escape, i, j;

  if (!arg)
    return 0;

  tok = strchr (arg, ',');
  num_of_escape = 0;

  /* make sure it is not escaped */
  while (tok)
    {
      if (*(tok-1) == '\\')
        {
          /* find the next one */
          tok = strchr (tok+1, ',');
          ++num_of_escape;
        }
      else
        break;
    }

  if (tok)
    len = (size_t)(tok - arg + 1);
  else
    len = strlen (arg) + 1;

  len -= num_of_escape;

  ret = (char *) malloc (len);

  i = 0;
  j = 0;
  while (arg[i] && (j < len-1))
    {
      if (arg[i] == '\\' && 
	  arg[ i + 1 ] && 
	  arg[ i + 1 ] == ',')
        ++i;

      ret[j++] = arg[i++];
    }

  ret[len-1] = '\0';

  return ret;
}

static const char *
get_multiple_arg_token_next(const char *arg)
{
  const char *tok;

  if (!arg)
    return 0;

  tok = strchr (arg, ',');

  /* make sure it is not escaped */
  while (tok)
    {
      if (*(tok-1) == '\\')
        {
          /* find the next one */
          tok = strchr (tok+1, ',');
        }
      else
        break;
    }

  if (! tok || strlen(tok) == 1)
    return 0;

  return tok+1;
}

static int
check_multiple_option_occurrences(const char *prog_name, unsigned int option_given, unsigned int min, unsigned int max, const char *option_desc);

int
check_multiple_option_occurrences(const char *prog_name, unsigned int option_given, unsigned int min, unsigned int max, const char *option_desc)
{
  int error_occurred = 0;

  if (option_given && (min > 0 || max > 0))
    {
      if (min > 0 && max > 0)
        {
          if (min == max)
            {
              /* specific occurrences */
              if (option_given != (unsigned int) min)
                {
                  fprintf (stderr, "%s: %s option occurrences must be %d\n",
                    prog_name, option_desc, min);
                  error_occurred = 1;
                }
            }
          else if (option_given < (unsigned int) min
                || option_given > (unsigned int) max)
            {
              /* range occurrences */
              fprintf (stderr, "%s: %s option occurrences must be between %d and %d\n",
                prog_name, option_desc, min, max);
              error_occurred = 1;
            }
        }
      else if (min > 0)
        {
          /* at least check */
          if (option_given < min)
            {
              fprintf (stderr, "%s: %s option occurrences must be at least %d\n",
                prog_name, option_desc, min);
              error_occurred = 1;
            }
        }
      else if (max > 0)
        {
          /* at most check */
          if (option_given > max)
            {
              fprintf (stderr, "%s: %s option occurrences must be at most %d\n",
                prog_name, option_desc, max);
              error_occurred = 1;
            }
        }
    }
    
  return error_occurred;
}
int
main_cmdline_parser (int argc, char **argv, struct main_args_info *args_info)
{
  return main_cmdline_parser2 (argc, argv, args_info, 0, 1, 1);
}

int
main_cmdline_parser_ext (int argc, char **argv, struct main_args_info *args_info,
                   struct main_cmdline_parser_params *params)
{
  int result;
  result = main_cmdline_parser_internal (argc, argv, args_info, params, 0);

  return result;
}

int
main_cmdline_parser2 (int argc, char **argv, struct main_args_info *args_info, int override, int initialize, int check_required)
{
  int result;
  struct main_cmdline_parser_params params;
  
  params.override = override;
  params.initialize = initialize;
  params.check_required = check_required;
  params.check_ambiguity = 0;
  params.print_errors = 1;

  result = main_cmdline_parser_internal (argc, argv, args_info, &params, 0);

  return result;
}

int
main_cmdline_parser_required (struct main_args_info *args_info, const char *prog_name)
{
  int result = EXIT_SUCCESS;

  if (main_cmdline_parser_required2(args_info, prog_name, 0) > 0)
    result = EXIT_FAILURE;

  return result;
}

int
main_cmdline_parser_required2 (struct main_args_info *args_info, const char *prog_name, const char *additional_error)
{
  int error_occurred = 0;
  FIX_UNUSED (additional_error);

  /* checks for required options */
  if (check_multiple_option_occurrences(prog_name, args_info->append_given, args_info->append_min, args_info->append_max, "'--append'"))
     error_occurred = 1;
  
  
  /* checks for dependences among options */

  return error_occurred;
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
 * @param check_ambiguity @see main_cmdline_parser_params.check_ambiguity
 * @param override @see main_cmdline_parser_params.override
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
               main_cmdline_parser_arg_type arg_type,
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

/**
 * @brief store information about a multiple option in a temporary list
 * @param list where to (temporarily) store multiple options
 */
static
int update_multiple_arg_temp(struct generic_list **list,
               unsigned int *prev_given, const char *val,
               const char *possible_values[], const char *default_value,
               main_cmdline_parser_arg_type arg_type,
               const char *long_opt, char short_opt,
               const char *additional_error)
{
  /* store single arguments */
  char *multi_token;
  const char *multi_next;

  if (arg_type == ARG_NO) {
    (*prev_given)++;
    return 0; /* OK */
  }

  multi_token = get_multiple_arg_token(val);
  multi_next = get_multiple_arg_token_next (val);

  while (1)
    {
      add_node (list);
      if (update_arg((void *)&((*list)->arg), &((*list)->orig), 0,
          prev_given, multi_token, possible_values, default_value, 
          arg_type, 0, 1, 1, 1, long_opt, short_opt, additional_error)) {
        if (multi_token) free(multi_token);
        return 1; /* failure */
      }

      if (multi_next)
        {
          multi_token = get_multiple_arg_token(multi_next);
          multi_next = get_multiple_arg_token_next (multi_next);
        }
      else
        break;
    }

  return 0; /* OK */
}

/**
 * @brief free the passed list (including possible string argument)
 */
static
void free_list(struct generic_list *list, short string_arg)
{
  if (list) {
    struct generic_list *tmp;
    while (list)
      {
        tmp = list;
        if (string_arg && list->arg.string_arg)
          free (list->arg.string_arg);
        if (list->orig)
          free (list->orig);
        list = list->next;
        free (tmp);
      }
  }
}

/**
 * @brief updates a multiple option starting from the passed list
 */
static
void update_multiple_arg(void *field, char ***orig_field,
               unsigned int field_given, unsigned int prev_given, union generic_value *default_value,
               main_cmdline_parser_arg_type arg_type,
               struct generic_list *list)
{
  int i;
  struct generic_list *tmp;

  if (prev_given && list) {
    *orig_field = (char **) realloc (*orig_field, (field_given + prev_given) * sizeof (char *));

    switch(arg_type) {
    case ARG_STRING:
      *((char ***)field) = (char **)realloc (*((char ***)field), (field_given + prev_given) * sizeof (char *)); break;
    default:
      break;
    };
    
    for (i = (prev_given - 1); i >= 0; --i)
      {
        tmp = list;
        
        switch(arg_type) {
        case ARG_STRING:
          (*((char ***)field))[i + field_given] = tmp->arg.string_arg; break;
        default:
          break;
        }        
        (*orig_field) [i + field_given] = list->orig;
        list = list->next;
        free (tmp);
      }
  } else { /* set the default value */
    if (default_value && ! field_given) {
      switch(arg_type) {
      case ARG_STRING:
        if (! *((char ***)field)) {
          *((char ***)field) = (char **)malloc (sizeof (char *));
          (*((char ***)field))[0] = gengetopt_strdup(default_value->string_arg);
        }
        break;
      default: break;
      }
      if (!(*orig_field)) {
        *orig_field = (char **) malloc (sizeof (char *));
        (*orig_field)[0] = 0;
      }
    }
  }
}

int
main_cmdline_parser_internal (
  int argc, char **argv, struct main_args_info *args_info,
                        struct main_cmdline_parser_params *params, const char *additional_error)
{
  int c;	/* Character of the parsed option.  */

  struct generic_list * append_list = NULL;
  int error_occurred = 0;
  struct main_args_info local_args_info;
  
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
    main_cmdline_parser_init (args_info);

  main_cmdline_parser_init (&local_args_info);

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
        { "all",	0, NULL, 0 },
        { "anonymize",	0, NULL, 0 },
        { "find-request-id",	0, NULL, 0 },
        { "sysconfdir",	1, NULL, 0 },
        { "output",	1, NULL, 'o' },
        { "append",	1, NULL, 0 },
        { "info",	0, NULL, 0 },
        { "logs",	0, NULL, 0 },
        { "cluster",	0, NULL, 0 },
        { "storage",	0, NULL, 0 },
        { 0,  0, 0, 0 }
      };

      c = getopt_long (argc, argv, "hVo:", long_options, &option_index);

      if (c == -1) break;	/* Exit from `while (1)' loop.  */

      switch (c)
        {
        case 'h':	/* Print help and exit.  */
          main_cmdline_parser_print_help ();
          main_cmdline_parser_free (&local_args_info);
          exit (EXIT_SUCCESS);

        case 'V':	/* Print version and exit.  */
        
        
          if (update_arg( 0 , 
               0 , &(args_info->version_given),
              &(local_args_info.version_given), optarg, 0, 0, ARG_NO,
              check_ambiguity, override, 0, 0,
              "version", 'V',
              additional_error))
            goto failure;
          main_cmdline_parser_free (&local_args_info);
          return 0;
        
          break;
        case 'o':	/* Save output to given file (default: sxreport-server-<timestamp>.log).  */
        
        
          if (update_arg( (void *)&(args_info->output_arg), 
               &(args_info->output_orig), &(args_info->output_given),
              &(local_args_info.output_given), optarg, 0, 0, ARG_STRING,
              check_ambiguity, override, 0, 0,
              "output", 'o',
              additional_error))
            goto failure;
        
          break;

        case 0:	/* Long option with no short option */
          if (strcmp (long_options[option_index].name, "full-help") == 0) {
            main_cmdline_parser_print_full_help ();
            main_cmdline_parser_free (&local_args_info);
            exit (EXIT_SUCCESS);
          }

          /* Print all the information below.  */
          if (strcmp (long_options[option_index].name, "all") == 0)
          {
          
          
            if (update_arg( 0 , 
                 0 , &(args_info->all_given),
                &(local_args_info.all_given), optarg, 0, 0, ARG_NO,
                check_ambiguity, override, 0, 0,
                "all", '-',
                additional_error))
              goto failure;
          
          }
          /* Anonymize IP addresses, URLs, and cluster usernames.  */
          else if (strcmp (long_options[option_index].name, "anonymize") == 0)
          {
          
          
            if (update_arg((void *)&(args_info->anonymize_flag), 0, &(args_info->anonymize_given),
                &(local_args_info.anonymize_given), optarg, 0, 0, ARG_FLAG,
                check_ambiguity, override, 1, 0, "anonymize", '-',
                additional_error))
              goto failure;
          
          }
          /* Print all messages corresponding to specified request ID.  */
          else if (strcmp (long_options[option_index].name, "find-request-id") == 0)
          {
          
          
            if (update_arg( 0 , 
                 0 , &(args_info->find_request_id_given),
                &(local_args_info.find_request_id_given), optarg, 0, 0, ARG_NO,
                check_ambiguity, override, 0, 0,
                "find-request-id", '-',
                additional_error))
              goto failure;
          
          }
          /* Path to /etc.  */
          else if (strcmp (long_options[option_index].name, "sysconfdir") == 0)
          {
          
          
            if (update_arg( (void *)&(args_info->sysconfdir_arg), 
                 &(args_info->sysconfdir_orig), &(args_info->sysconfdir_given),
                &(local_args_info.sysconfdir_given), optarg, 0, 0, ARG_STRING,
                check_ambiguity, override, 0, 0,
                "sysconfdir", '-',
                additional_error))
              goto failure;
          
          }
          /* Append information from specified file (- is stdin), anonymized only if --anonymize is specified.  */
          else if (strcmp (long_options[option_index].name, "append") == 0)
          {
          
            if (update_multiple_arg_temp(&append_list, 
                &(local_args_info.append_given), optarg, 0, 0, ARG_STRING,
                "append", '-',
                additional_error))
              goto failure;
          
          }
          /* Print static configuration only.  */
          else if (strcmp (long_options[option_index].name, "info") == 0)
          {
          
          
            if (update_arg( 0 , 
                 0 , &(args_info->info_given),
                &(local_args_info.info_given), optarg, 0, 0, ARG_NO,
                check_ambiguity, override, 0, 0,
                "info", '-',
                additional_error))
              goto failure;
          
          }
          /* Print error messages from logs only (NOT anonymized).  */
          else if (strcmp (long_options[option_index].name, "logs") == 0)
          {
          
          
            if (update_arg( 0 , 
                 0 , &(args_info->logs_given),
                &(local_args_info.logs_given), optarg, 0, 0, ARG_NO,
                check_ambiguity, override, 0, 0,
                "logs", '-',
                additional_error))
              goto failure;
          
          }
          /* Print information about cluster's status & health.  */
          else if (strcmp (long_options[option_index].name, "cluster") == 0)
          {
          
          
            if (update_arg( 0 , 
                 0 , &(args_info->cluster_given),
                &(local_args_info.cluster_given), optarg, 0, 0, ARG_NO,
                check_ambiguity, override, 0, 0,
                "cluster", '-',
                additional_error))
              goto failure;
          
          }
          /* Print information about the node's local storage.  */
          else if (strcmp (long_options[option_index].name, "storage") == 0)
          {
          
          
            if (update_arg( 0 , 
                 0 , &(args_info->storage_given),
                &(local_args_info.storage_given), optarg, 0, 0, ARG_NO,
                check_ambiguity, override, 0, 0,
                "storage", '-',
                additional_error))
              goto failure;
          
          }
          
          break;
        case '?':	/* Invalid option.  */
          /* `getopt_long' already printed an error message.  */
          goto failure;

        default:	/* bug: option not considered.  */
          fprintf (stderr, "%s: option unknown: %c%s\n", MAIN_CMDLINE_PARSER_PACKAGE, c, (additional_error ? additional_error : ""));
          abort ();
        } /* switch */
    } /* while */


  update_multiple_arg((void *)&(args_info->append_arg),
    &(args_info->append_orig), args_info->append_given,
    local_args_info.append_given, 0,
    ARG_STRING, append_list);

  args_info->append_given += local_args_info.append_given;
  local_args_info.append_given = 0;
  
  if (check_required)
    {
      error_occurred += main_cmdline_parser_required2 (args_info, argv[0], additional_error);
    }

  main_cmdline_parser_release (&local_args_info);

  if ( error_occurred )
    return (EXIT_FAILURE);

  return 0;

failure:
  free_list (append_list, 1 );
  
  main_cmdline_parser_release (&local_args_info);
  return (EXIT_FAILURE);
}
