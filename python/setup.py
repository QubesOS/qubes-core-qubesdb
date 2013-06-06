
from distutils.core import setup, Extension

extra_compile_args  = [ "-fno-strict-aliasing", "-Werror" ]

PATH_INCLUDES      = "../include"
PATH_LIBS          = "../client"

qdb = Extension("qdb",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ PATH_INCLUDES ],
               library_dirs       = [ PATH_LIBS ],
               libraries          = [ "qubesdb" ],
               depends            = [ PATH_LIBS + "/libqubesdb.so" ],
               sources            = [ "qdb.c" ])

setup(name            = 'QubesDB',
      version         = '1.0',
      description     = 'Qubes DB',
      ext_package = "qubes",
      ext_modules = [ qdb ]
      )
