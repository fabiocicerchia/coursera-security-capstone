CREATE TABLE users (
	id int(11) not null auto_increment,
	hash varchar(64) not null,
	username varchar(1024) not null,
	email varchar(1024) not null,
	password varchar(64) not null,
	salt varchar(64) not null,
	key: Encrypt (adapt)
	key_priv text not null,
	key_pub text not null,
	active tinyint(1) not null default 0,
	attempts int(11) not null default 0
	locked_until datetime null,
	primary key (id)
) ENGINE=InnoDB;

CREATE TABLE tokens (
	id int(11) not null auto_increment,
	user_id int(11) not null,
	reset_token varchar(64) not null,
	expire datetime not null,
	used tinyint(1) not null default 0,
	ip_request int(11) not null,
	ip_used int(11) null,
	primary key (id)
) ENGINE=InnoDB;

CREATE TABLE messages (
	id int(11) not null auto_increment,
	user_id int(11) not null,
	from int(11) not null,
	to int(11) not null,
	message text not null,
	date datetime not null,
	primary key (id)
) ENGINE=InnoDB;
