Acl = function Resources() {

	this._roles = [];
	this._resources = [];
	this._permissions = [];

	this._messages = {
		exception: {
			invalidFormat: 'only A-Z, 0-9 and - chars are allowed',
			emptyFormat: 'value should be defined'
		}
	}

};

Acl.prototype._validateFormat = function(value) {

	if(!value) {

		throw this._messages.exception.emptyFormat;

	}

	if(value.match(/[^a-z0-9-]/ig)) {

		throw this._messages.exception.invalidFormat;

	}

}

Acl.prototype.addRole = function(role) {

	this._validateFormat(role);
	this._roles.push(role);

	return true;

}

Acl.prototype.hasRole = function(role) {

	this._validateFormat(role);

	var i = 0;

	for (; i < this._roles.length; i++) {

		if(this._roles[i] == role) {

			return true;

		}
		
	}

	return false;

}

Acl.prototype.addResource = function(resource) {

	this._validateFormat(resource);
	this._resources.push(resource);

	return true;

}

Acl.prototype.hasResource = function(resource) {

	this._validateFormat(resource);

	var i = 0;

	for (; i < this._resources.length; i++) {

		if(this._resources[i] == resource) {

			return true;

		}
		
	}

	return false;

}

Acl.prototype.addRule = function(role, resource, permissions) {

	this._validateFormat(role);
	this._validateFormat(resource);

	if(!Array.isArray(permissions)) {
		permissions = [permissions];
	}

	var i = 0;	

	for (; i < permissions.length; i++) {
		this._validateFormat(permissions[i]);
	}

	if(this._hasRule(role, resource, permissions)) {
		return false;
	}

	var access = {
		role: role,
		resource: resource,
		permissions: permissions
	}

	this._permissions.push(access);

	return true;

}

Acl.prototype._hasRule = function(role, resource, permissions) {

	var i = 0,
		x = 0,
		z = 0;

	for (; i < this._permissions.length; i++) {

		var permission = this._permissions[i];

		if(permission.role == role &&
			permission.resource == resource) {
			
			for (; x < permission.permissions.length; x++) {

				var rule = permission.permissions[x];

				for (; z < permissions.length; z++) {
					
					if(rule == permissions[z]) {

						return true;

					}

				}

			}

		}

	}

	return false;

}

Acl.prototype.hasAccess = function(role, resource, permissions) {

	this._validateFormat(role);
	this._validateFormat(resource);

	if(!Array.isArray(permissions)) {
		permissions = [permissions];
	}

	var i = 0;	

	for (; i < permissions.length; i++) {
		this._validateFormat(permissions[i]);
	}	

	return this._hasRule(role, resource, permissions);

}

exports.Acl = Acl;