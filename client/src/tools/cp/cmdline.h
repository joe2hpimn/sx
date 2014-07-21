/** @file cmdline.h
 *  @brief The header file for the command line option parser
 *  generated by GNU Gengetopt version 2.22.6
 *  http://www.gnu.org/software/gengetopt.
 *  DO NOT modify this file, since it can be overwritten
 *  @author GNU Gengetopt by Lorenzo Bettini */

#ifndef CMDLINE_H
#define CMDLINE_H

/* If we use autoconf.  */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h> /* for FILE */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef CMDLINE_PARSER_PACKAGE
/** @brief the program name (used for printing errors) */
#define CMDLINE_PARSER_PACKAGE "sxcp"
#endif

#ifndef CMDLINE_PARSER_PACKAGE_NAME
/** @brief the complete program name (used for help and version) */
#define CMDLINE_PARSER_PACKAGE_NAME "sxcp"
#endif

#ifndef CMDLINE_PARSER_VERSION
/** @brief the program version */
#define CMDLINE_PARSER_VERSION VERSION
#endif

/** @brief Where the command line options are stored */
struct gengetopt_args_info
{
  const char *help_help; /**< @brief Print help and exit help description.  */
  const char *full_help_help; /**< @brief Print help, including hidden options, and exit help description.  */
  const char *version_help; /**< @brief Print version and exit help description.  */
  int recursive_flag;	/**< @brief Recursively copy files from SOURCE to DEST directory (default=off).  */
  const char *recursive_help; /**< @brief Recursively copy files from SOURCE to DEST directory help description.  */
  int one_file_system_flag;	/**< @brief Don't cross filesystem boundaries (default=off).  */
  const char *one_file_system_help; /**< @brief Don't cross filesystem boundaries help description.  */
  char * bwlimit_arg;	/**< @brief Set bandwidth usage limit in kilobytes per second (allows K, M, G suffixes, assume K when no suffix given).  */
  char * bwlimit_orig;	/**< @brief Set bandwidth usage limit in kilobytes per second (allows K, M, G suffixes, assume K when no suffix given) original value given at command line.  */
  const char *bwlimit_help; /**< @brief Set bandwidth usage limit in kilobytes per second (allows K, M, G suffixes, assume K when no suffix given) help description.  */
  int no_progress_flag;	/**< @brief Don't output progress bar (default=off).  */
  const char *no_progress_help; /**< @brief Don't output progress bar help description.  */
  int verbose_flag;	/**< @brief Print more details about the upload (default=off).  */
  const char *verbose_help; /**< @brief Print more details about the upload help description.  */
  int debug_flag;	/**< @brief Enable debug messages (default=off).  */
  const char *debug_help; /**< @brief Enable debug messages help description.  */
  char * config_dir_arg;	/**< @brief Path to SX configuration directory.  */
  char * config_dir_orig;	/**< @brief Path to SX configuration directory original value given at command line.  */
  const char *config_dir_help; /**< @brief Path to SX configuration directory help description.  */
  char * filter_dir_arg;	/**< @brief Path to SX filter directory.  */
  char * filter_dir_orig;	/**< @brief Path to SX filter directory original value given at command line.  */
  const char *filter_dir_help; /**< @brief Path to SX filter directory help description.  */
  int total_conns_limit_arg;	/**< @brief Limit number of connections (default='5').  */
  char * total_conns_limit_orig;	/**< @brief Limit number of connections original value given at command line.  */
  const char *total_conns_limit_help; /**< @brief Limit number of connections help description.  */
  int host_conns_limit_arg;	/**< @brief Limit number of connections with one host (default='2').  */
  char * host_conns_limit_orig;	/**< @brief Limit number of connections with one host original value given at command line.  */
  const char *host_conns_limit_help; /**< @brief Limit number of connections with one host help description.  */
  char * dot_size_arg;	/**< @brief Use specified size for each dot printed with file transfer progress (short: 1KB, long: 8KB, scale: block size).  */
  char * dot_size_orig;	/**< @brief Use specified size for each dot printed with file transfer progress (short: 1KB, long: 8KB, scale: block size) original value given at command line.  */
  const char *dot_size_help; /**< @brief Use specified size for each dot printed with file transfer progress (short: 1KB, long: 8KB, scale: block size) help description.  */
  
  unsigned int help_given ;	/**< @brief Whether help was given.  */
  unsigned int full_help_given ;	/**< @brief Whether full-help was given.  */
  unsigned int version_given ;	/**< @brief Whether version was given.  */
  unsigned int recursive_given ;	/**< @brief Whether recursive was given.  */
  unsigned int one_file_system_given ;	/**< @brief Whether one-file-system was given.  */
  unsigned int bwlimit_given ;	/**< @brief Whether bwlimit was given.  */
  unsigned int no_progress_given ;	/**< @brief Whether no-progress was given.  */
  unsigned int verbose_given ;	/**< @brief Whether verbose was given.  */
  unsigned int debug_given ;	/**< @brief Whether debug was given.  */
  unsigned int config_dir_given ;	/**< @brief Whether config-dir was given.  */
  unsigned int filter_dir_given ;	/**< @brief Whether filter-dir was given.  */
  unsigned int total_conns_limit_given ;	/**< @brief Whether total-conns-limit was given.  */
  unsigned int host_conns_limit_given ;	/**< @brief Whether host-conns-limit was given.  */
  unsigned int dot_size_given ;	/**< @brief Whether dot-size was given.  */

  char **inputs ; /**< @brief unamed options (options without names) */
  unsigned inputs_num ; /**< @brief unamed options number */
} ;

/** @brief The additional parameters to pass to parser functions */
struct cmdline_parser_params
{
  int override; /**< @brief whether to override possibly already present options (default 0) */
  int initialize; /**< @brief whether to initialize the option structure gengetopt_args_info (default 1) */
  int check_required; /**< @brief whether to check that all required options were provided (default 1) */
  int check_ambiguity; /**< @brief whether to check for options already specified in the option structure gengetopt_args_info (default 0) */
  int print_errors; /**< @brief whether getopt_long should print an error message for a bad option (default 1) */
} ;

/** @brief the purpose string of the program */
extern const char *gengetopt_args_info_purpose;
/** @brief the usage string of the program */
extern const char *gengetopt_args_info_usage;
/** @brief the description string of the program */
extern const char *gengetopt_args_info_description;
/** @brief all the lines making the help output */
extern const char *gengetopt_args_info_help[];
/** @brief all the lines making the full help output (including hidden options) */
extern const char *gengetopt_args_info_full_help[];

/**
 * The command line parser
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser (int argc, char **argv,
  struct gengetopt_args_info *args_info);

/**
 * The command line parser (version with additional parameters - deprecated)
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @param override whether to override possibly already present options
 * @param initialize whether to initialize the option structure my_args_info
 * @param check_required whether to check that all required options were provided
 * @return 0 if everything went fine, NON 0 if an error took place
 * @deprecated use cmdline_parser_ext() instead
 */
int cmdline_parser2 (int argc, char **argv,
  struct gengetopt_args_info *args_info,
  int override, int initialize, int check_required);

/**
 * The command line parser (version with additional parameters)
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @param params additional parameters for the parser
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_ext (int argc, char **argv,
  struct gengetopt_args_info *args_info,
  struct cmdline_parser_params *params);

/**
 * Save the contents of the option struct into an already open FILE stream.
 * @param outfile the stream where to dump options
 * @param args_info the option struct to dump
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_dump(FILE *outfile,
  struct gengetopt_args_info *args_info);

/**
 * Save the contents of the option struct into a (text) file.
 * This file can be read by the config file parser (if generated by gengetopt)
 * @param filename the file where to save
 * @param args_info the option struct to save
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_file_save(const char *filename,
  struct gengetopt_args_info *args_info);

/**
 * Print the help
 */
void cmdline_parser_print_help(void);
/**
 * Print the full help (including hidden options)
 */
void cmdline_parser_print_full_help(void);
/**
 * Print the version
 */
void cmdline_parser_print_version(void);

/**
 * Initializes all the fields a cmdline_parser_params structure 
 * to their default values
 * @param params the structure to initialize
 */
void cmdline_parser_params_init(struct cmdline_parser_params *params);

/**
 * Allocates dynamically a cmdline_parser_params structure and initializes
 * all its fields to their default values
 * @return the created and initialized cmdline_parser_params structure
 */
struct cmdline_parser_params *cmdline_parser_params_create(void);

/**
 * Initializes the passed gengetopt_args_info structure's fields
 * (also set default values for options that have a default)
 * @param args_info the structure to initialize
 */
void cmdline_parser_init (struct gengetopt_args_info *args_info);
/**
 * Deallocates the string fields of the gengetopt_args_info structure
 * (but does not deallocate the structure itself)
 * @param args_info the structure to deallocate
 */
void cmdline_parser_free (struct gengetopt_args_info *args_info);

/**
 * Checks that all the required options were specified
 * @param args_info the structure to check
 * @param prog_name the name of the program that will be used to print
 *   possible errors
 * @return
 */
int cmdline_parser_required (struct gengetopt_args_info *args_info,
  const char *prog_name);


#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* CMDLINE_H */
