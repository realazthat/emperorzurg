

### Notes


Depends on freenode-style cloaks for authentication.


Make sure to configure the admin cloak in the yml configuration file
(see `voice_master_bot_config.default.yml`). Add your cloak to 
the `default_admins` list.


Rename the configuration file to something else, for example,
`voice_master_bot_config.yml`. Run the program with:

    python voice_master_bot.py voice_master_bot_config.yml


For information on commands:

    /msg emperorzurg !help


###Required libs

#### Python libs

* ircutils
* twisted
* pyyaml


