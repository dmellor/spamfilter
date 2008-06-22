-- Run schema/convert_greylist.py before running this script.

-- April 20, 2008.
-- Add not null constraints.
alter table greylist alter successful set not null;
alter table greylist alter unsuccessful set not null;
alter table users alter name drop default;

-- Add a primary key to the user_addresses table.
create sequence user_addresses_id_seq;
create table foo (
	id integer,
	address varchar(255) not null,
	user_id integer not null
);
insert into foo (address, user_id) select * from user_addresses;
update foo set id = nextval('user_addresses_id_seq');
alter table foo alter id set default nextval('user_addresses_id_seq');
drop table user_addresses;
alter table foo rename to user_addresses;
alter table user_addresses add primary key (id);
alter table user_addresses
	add constraint user_addresses_fkey
	foreign key (user_id) references users (id)
	on delete cascade;
grant select, insert, update, delete on user_addresses to qmail;

-- Rearranging the whitelist_from table - may be deleted.
--create table foo (
--	id integer,
--	user_id integer not null,
--	mail_from varchar(255) not null,
--	regexp varchar(255) not null
--);
--insert into foo (id, user_id, mail_from, regexp)
--	select id, user_id, mail_from, regexp from whitelist_from;
--drop sequence whitelist_from_id_seq;
--drop table whitelist_from;
--alter table foo rename to whitelist_from;
--create sequence whitelist_from_id_seq;
--select setval('whitelist_from_id_seq', (select max(id) from whitelist_from));
--alter table whitelist_from alter id
--	set default nextval('whitelist_from_id_seq');
--alter table whitelist_from add primary key (id);
--alter table whitelist_from
--	add constraint whitelist_from_fkey
--	foreign key (user_id) references users (id)
--	on delete cascade;
--grant select, insert, update, delete on whitelist_from to qmail;
--create trigger whitelist_from_regexp
--	before insert or update on whitelist_from
--	for each row execute procedure convert_whitelist_from();

-- Resetting the length of the ip_address column in the greylist table.
create table foo (
	id integer,
	ip_address varchar(11) not null,
	mail_from varchar(1024) not null,
	rcpt_to varchar(1024) not null,
	created timestamp with time zone not null default now(),
	modified timestamp with time zone not null,
	successful integer not null default 0,
	unsuccessful integer not null default 0
);
insert into foo (id, ip_address, mail_from, rcpt_to, created, modified,
	successful, unsuccessful)
	select id, ip_address, mail_from, rcpt_to, created, modified, successful,
		unsuccessful from greylist;
drop table greylist;
alter table foo rename to greylist;
create sequence greylist_id_seq;
select setval('greylist_id_seq', (select max(id) from greylist));
alter table greylist alter id set default nextval('greylist_id_seq');
alter table greylist add primary key (id);
create unique index greylist_tuple on greylist
	(ip_address, mail_from, rcpt_to);
create index greylist_ip_address on greylist (ip_address);
create index greylist_mail_from on greylist (mail_from);
grant select, insert, update, delete on greylist to qmail;
create trigger greylist_stamp
	before insert or update on greylist
	for each row execute procedure stamp();

-- Drop unnecessary tables.
drop table classc_domains;
drop table logs;
