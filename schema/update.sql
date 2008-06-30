-- Run schema/convert_greylist.py before running this script.

-- April 20, 2008.
-- Resetting the length of the ip_address column in the greylist table.
create table foo (
	id integer,
	ip_address varchar(11) not null,
	mail_from varchar(1024),
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
grant select, insert, update, delete on greylist_id_seq to qmail;
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

-- June 28, 2008
-- Adding a primary key to the saved_mail_recipients table, and renaming it.
create table foo (
	id integer,
	recipient varchar(1024) not null,
	spam_id integer not null,
	delivery_id varchar(32)
);
insert into foo (recipient, spam_id, delivery_id)
	select recipient, saved_mail_id, delivery_id from saved_mail_recipients;
drop table saved_mail_recipients;
alter table foo rename to spam_recipients;
create sequence spam_recipients_id_seq;
grant select, insert, update, delete on spam_recipients_id_seq to qmail;
update spam_recipients set id = nextval('spam_recipients_id_seq');
alter table spam_recipients
	alter id set default nextval('spam_recipients_id_seq');
alter table spam_recipients add primary key (id);
create table foo (
	id integer,
	mail_from varchar(1024),
	ip_address varchar(15) not null,
	contents text not null,
	score double precision not null,
	tests text not null,
	created timestamp with time zone not null default now()
);
insert into foo (id, mail_from, ip_address, contents, score, tests, created)
	select id, mail_from, ip_address, contents, hits, tests, created
		from saved_mail;
drop table saved_mail;
alter table foo rename to spam;
create sequence spam_id_seq;
grant select, insert, update, delete on spam_id_seq to qmail;
alter table spam alter id set default nextval('spam_id_seq');
alter table spam add primary key (id);
grant select, insert, update, delete on spam to qmail;
alter table spam_recipients
	add constraint spam_recipients_fkey
	foreign key (spam_id) references spam (id)
	on delete cascade;
grant select, insert, update, delete on spam_recipients to qmail;

-- Adding a primary key to the virus_recipients table.
create table foo (
	id integer,
	recipient varchar(1024) not null,
	virus_id integer not null
);
insert into foo (recipient, virus_id)
	select recipient, virus_id from virus_recipients;
drop table virus_recipients;
alter table foo rename to virus_recipients;
create sequence virus_recipients_id_seq;
grant select, insert, update, delete on virus_recipients_id_seq to qmail;
update virus_recipients set id = nextval('virus_recipients_id_seq');
alter table virus_recipients
	alter id set default nextval('virus_recipients_id_seq');
alter table virus_recipients add primary key (id);
create table foo (
	id integer,
	mail_from varchar(1024),
	ip_address varchar(15) not null,
	contents text not null,
	virus varchar(1024) not null,
	created timestamp with time zone not null default now()
);
insert into foo (id, mail_from, ip_address, contents, virus, created)
	select id, mail_from, ip_address, contents, virus, created from viruses;
drop table viruses;
alter table foo rename to viruses;
create sequence viruses_id_seq;
grant select, insert, update, delete on viruses_id_seq to qmail;
alter table viruses alter id set default nextval('viruses_id_seq');
select setval('viruses_id_seq', (select max(id) from viruses));
alter table viruses add primary key (id);
grant select, insert, update, delete on viruses to qmail;
alter table virus_recipients
	add constraint virus_recipients_fkey
	foreign key (virus_id) references viruses (id)
	on delete cascade;
grant select, insert, update, delete on virus_recipients to qmail;

-- Reformat the auto_whitelist table so that it can be used by
-- Mail::SpamAssassin::SQLBasedAddrList.
create table foo (
	id integer,
	username varchar(1024),
	email varchar(1024) not null,
	ip varchar(15) not null,
	count integer not null,
	totscore double precision not null,
	created timestamp with time zone not null default now(),
	modified timestamp with time zone not null
);
insert into foo (id, email, ip, count, totscore, created, modified)
	select id, address, ip, count, score, created, modified
	from auto_whitelist;
drop table auto_whitelist;
alter table foo rename to auto_whitelist;
create sequence auto_whitelist_id_seq;
grant select, insert, update, delete on auto_whitelist_id_seq to qmail;
grant select, insert, update, delete on auto_whitelist to qmail;
alter table auto_whitelist alter id
	set default nextval('auto_whitelist_id_seq');
select setval('auto_whitelist_id_seq', (select max(id) from auto_whitelist));
alter table auto_whitelist add primary key (id);
update auto_whitelist set username = 'GLOBAL';
alter table auto_whitelist alter username set not null;
create unique index auto_whitelist_address_index
	on auto_whitelist (username, email, ip);
create trigger auto_whitelist_stamp
	before insert or update on auto_whitelist
	for each row execute procedure stamp();

-- Drop unnecessary tables.
drop table blacklist;
drop table user_addresses;
drop table whitelist_from;
drop table users;
