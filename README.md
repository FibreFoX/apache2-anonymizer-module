Apache2 - Anonymizer Module
===========================

License: Apache2

Steps for creating
==================
* install apache2-dev package `apt-get install apache2-dev`
* download `anonymizer_module.c`
* execute `apxs2 -i -a -c anonymizer_module.c`
* reload apache2
* add `Anonymize on` to your vhost-configuration