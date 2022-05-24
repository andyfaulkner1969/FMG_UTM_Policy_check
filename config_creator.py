from configparser import ConfigParser

config = ConfigParser()


config['settings'] = {
    'fmg_ip' : '192.168.75.201',
    'fmg_user': 'api-user',
    'adom_exclude': ["FortiAnalyzer", "FortiAuthenticator", "FortiCache", "FortiCarrier", "FortiClient",
                "FortiDDoS", "FortiDeceptor", "FortiFirewall", "FortiFirewallCarrier", "FortiMail",
                "FortiManager", "FortiNAC", "FortiProxy", "FortiSandbox", "FortiWeb", "Unmanaged_Devices",
                "rootp", "others", "Syslog"],
    'fmg_passwd':'NONE'
}

config.set('settings', '; Leave NONE if you want to use "GetPass" on command line or hardcode to your password', '')

config['debug'] = {
    'debug':'False',
    'log_to_file': 'Fasle',
    'log_file':'script_master.log',
    'debug_log_path':'./'
}

config['directory'] = {
    'cli_path':'./'
}

with open ('script_master.ini','w') as f:
    config.write(f)