
from distutils.core import setup, Extension

extra_compile_args  = [ "-fno-strict-aliasing", "-Werror" ]

PATH_INCLUDES      = "../include"
PATH_LIBS          = "../client"

qubesdb = Extension("qubesdb",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ PATH_INCLUDES ],
               library_dirs       = [ PATH_LIBS ],
               libraries          = [ "qubesdb" ],
               sources            = [ "qubesdb.c" ])

setup(name            = 'QubesDB',
      version         = '1.0',
      description     = 'Qubes DB',
      #ext_package = "",
      ext_modules = [ qubesdb ]
      )
