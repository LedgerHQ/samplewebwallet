require('Sandbox');
require('HidapiPlugupCardTerminal');

var HidapiPlugupCardTerminalFactory = Class.extend(CardTerminalFactory, {
	/** @lends PPACardTerminalFactory.prototype */
	
	/**
	 *  @class Implementation of the {@link CardTerminalFactory} using the generic HID for Plug-up Dongle
	 *  @constructs
	 *  @augments CardTerminalFactory
	 */				
	initialize: function() {
		/*
		if (Sandbox.getInstance().isSealed()) {
			throw "Security violation";
		}	
		*/
	},
	
	list: function() {
	    var plugin = document.getElementById("hidapiPlugin");
	    var result = plugin.hid_enumerate();
	    var paths = [];
	    for (var i=0; i<result.length; i++) {
			if ((result[i]["vendor_id"] == 0x2581) && (result[i]["product_id"] == 0x1807) && 
				((result[i]["interface_number"] == 1) || (result[i]["usage_page"] == 65440))) {
				paths.push(result[i]["path"])
				break;
			}
		}
		return paths;
	},

	waitInserted: function() {
		throw "Not implemented"
	},

	getCardTerminal: function(name, options) {
		return new HidapiPlugupCardTerminal(name, options);
	}
});
