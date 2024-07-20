drop table if exists users CASCADE;
create table users
(
    username varchar(50) primary key,
    password varchar(255),
    enabled  boolean
);

drop table if exists authorities CASCADE;
create table authorities
(
    username varchar(50) not null references users,
    authority varchar(50) not null
);

drop table if exists groups CASCADE;
create table groups
(
    id       bigserial primary key,
    group_name varchar(50) not null
);

drop table if exists group_authorities CASCADE;
create table group_authorities
(
    group_id       bigserial primary key,
    authority varchar(50) not null
);


drop table if exists group_members CASCADE;
create table group_members
(
    id       bigserial primary key,
    username varchar(50) not null references users,
    group_id bigint not null
);