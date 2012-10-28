var	Acl = require('../../vitsaus-acl/acl.js').Acl;

describe('acl', function() {

	var acl = new Acl();

	it('should not add role because of invalid role name', function() {
		expect(function() {
			acl.addRole('guest_');
		}).toThrow(acl._messages.exception.invalidFormat);
	});

	it('should add role', function() {
		var result = acl.addRole('guest');
		expect(result).toBe(true);
	});

	it('should have role', function() {
		var result = acl.hasRole('guest');
		expect(result).toBe(true);		
	});

	it('should not add resource because of invalid resource name', function() {
		expect(function() {
			acl.addResource('user_');
		}).toThrow(acl._messages.exception.invalidFormat);
	});

	it('should add resource', function() {
		var result = acl.addResource('user-model');
		expect(result).toBe(true);
	});

	it('should have resource', function() {
		var result = acl.hasResource('user-model');
		expect(result).toBe(true);
	});

	it('should add rules', function() {
		var result = acl.addRule('guest', 'user-model', ['login']);
		expect(result).toBe(true);
		result = acl.addRule('guest', 'user-model', ['register']);
		expect(result).toBe(true);		
	});

	it('should not add rule because rule exists', function() {
		var result = acl.addRule('guest', 'user-model', ['login']);
		expect(result).toBe(false);
	});

	it('should not add rule because of invalid role format', function() {
		expect(function() {
			acl.addRule('guest_', 'user-model', ['login']);
		}).toThrow(acl._messages.exception.invalidFormat);
	});

	it('should not add rule because of invalid resource format', function() {
		expect(function() {
			acl.addRule('guest', 'user-model_', ['login']);
		}).toThrow(acl._messages.exception.invalidFormat);
	});	

	it('should not add rule because of invalid permission format', function() {
		expect(function() {
			acl.addRule('guest', 'user-model_', ['login', 'logout_']);
		}).toThrow(acl._messages.exception.invalidFormat);
	});	

	it('should not have rule', function() {
		var result = acl._hasRule('guest', 'user-model', ['logout']);
		expect(result).toBe(false);
	});

	it('should have rule', function() {
		var result = acl._hasRule('guest', 'user-model', ['login']);
		expect(result).toBe(true);
	});

	it('should have access', function() {
		var result = acl.hasAccess('guest', 'user-model', ['login']);
		expect(result).toBe(true);
	});

	it('should not have access', function() {
		var result = acl.hasAccess('guest', 'user-model', ['logout']);
		expect(result).toBe(false);		
	});

});
