AC_DEFUN([MY_STATUS],
[
    m4_if($#,4,,[m4_fatal([$0: invalid number of arguments: $#])])
    AS_ECHO_N(["    $1 library: "])
    AS_IF([test "$2" = "no"], [AS_ECHO(["(use embedded)"])],
          [test "$2" = "yes"], [
            AS_ECHO(["(use system) $3 $4"]);
        ])
])
