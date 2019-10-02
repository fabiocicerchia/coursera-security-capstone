CREATE TABLE users (
        id serial not null,
        hash varchar(64) not null,
        username varchar(1024) not null,
        email varchar(1024) not null,
        password varchar(64) not null,
        salt varchar(64) not null,
        key_priv text not null,
        key_pub text not null,
        active boolean not null default false,
        attempts int not null default 0,
        locked_until timestamp null,
        primary key (id)
);

CREATE TABLE tokens (
        id serial not null,
        user_id int not null,
        reset_token varchar(255) not null,
        expire timestamp not null,
        used boolean not null default false,
        ip_request varchar(1024) not null,
        ip_used varchar(1024),
        primary key (id)
);

CREATE TABLE messages (
        id serial not null,
        user_id int not null,
        user_from int not null,
        user_to int not null,
        message text not null,
        date timestamp not null,
        read boolean default false,
        primary key (id)
);
