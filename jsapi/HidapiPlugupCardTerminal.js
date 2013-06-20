require('Sandbox');
require('CardTerminal');
require('HidapiPlugupCard');
require('Convert');

var HidapiPlugupCardTerminal = Class.extend(CardTerminal, {
	/** @lends PPACardTerminal.prototype */
	
	/**
	 *  @class In browser implementation of the {@link CardTerminal} interface using the Plugup Proxy Applet
	 *  @param {String} terminalName Name of the terminal
	 *  @constructs
	 *  @augments CardTerminal
	 */	
	initialize: function(name, options) {
		/*
		if (Sandbox.getInstance().isSealed()) {
			throw "Security violation";
		}
		*/
		if (typeof name == "undefined") {
			name = "";
		}
		this.terminalName = name;
		this.options = options;
	},
	
	isCardPresent:function() {
		return true;
	},
	
	getCard:function() {
		if (typeof this.cardInstance == "undefined") {
			this.cardInstance = new HidapiPlugupCard(this);
		}
		return this.cardInstance;
	},
		
	getTerminalName:function() {
		return this.terminalName;
	},

	getOptions:function() { 
		return this.options;
	},
	
	getName:function() {		
		if (this.terminalName.length == 0) {
			return "Default";
		}
		else {
			return this.terminalName;
		}
	}
			
});
