##Privacy Item Wildcard Plugin Readme

**Overview**

This plugin is used to expand privacy list function. As described in XEP-0016, <domain/resource> should be supported in JID match, which Openfire currently doesn't support. This plugin add this support, i.e. block messages filtered by <domain/resource> with type 'jid'.

**Installation**

Copy the file, PrivacyItemWildcard.jar into the plugins directory of your Openfire installation. The plugin will then be automatically deployed. To upgrade to a new version: 1) go to the plugin screen of the Admin
Console, 2) click on the delete icon on the same row as the currently installed subscription plugin, 3) 
copy the new subscription.jar into the plugins directory of your Openfire installation.

**Using the Plugin**

Once the plugin has been installed and configured there is no additional steps are required to use the plugin.