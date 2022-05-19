This is a script that runs against the FortiManager via the JSON  

It gets a list of ADOMS, then a list of policy packages in each ADOM.
Then it will scan each policy for UTM functions.  It will log the results to a CSV file.

The name of the CSV file is defined in the script and can be changed.

first version will prompt for the FMG api user password using getpass

The FMG IP address and the FMG api user are hard coded and need to be changed to match your values.

I have a lot more information to add here.
