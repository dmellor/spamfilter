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

-- Rearranging the whitelist_from table.
create table foo (
	id integer,
	user_id integer not null,
	mail_from varchar(255) not null,
	regexp varchar(255) not null
);
insert into foo (id, user_id, mail_from, regexp)
	select id, user_id, mail_from, regexp from whitelist_from;
alter table foo alter id set default nextval('whitelist_from_id_seq');
drop table whitelist_from;
alter table foo rename to whitelist_from;
alter table whitelist_from add primary key (id);
alter table whitelist_from
	add constraint whitelist_from_fkey
	foreign key (user_id) references users (id)
	on delete cascade;
grant select, insert, update, delete on whitelist_from to qmail;
create trigger whitelist_from_regexp
	before insert or update on whitelist_from
	for each row execute procedure convert_whitelist_from();
