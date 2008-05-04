import os, sys
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from model.greylist import Greylist

Session = sessionmaker(autoflush=False, transactional=True)

class GreylistWrapper(object):
    def __init__(self, greylist):
        self.mail_from = greylist.mail_from
        self.rcpt_to = greylist.rcpt_to
        self.ip_address = '.'.join(greylist.ip_address.split('.')[:3])

    def __eq__(self, obj):
        return self.mail_from == obj.mail_from and \
               self.rcpt_to == obj.rcpt_to and \
               self.ip_address == obj.ip_address

    def __hash__(self):
        return hash(self.mail_from)

def main(user, password):
    dburi = 'postgres://%s:%s@localhost/spamassassin' % (user, password)
    engine = create_engine(dburi, convert_unicode=False, echo=False)
    session = Session(bind=engine.connect())
    session.connection().execute('drop trigger greylist_stamp on greylist')
    objs = session.query(Greylist).all()
    retained = {}
    for obj in objs:
        wrapper = GreylistWrapper(obj)
        retained_obj = retained.get(wrapper)
        if retained_obj:
            retained_obj.successful += obj.successful
            retained_obj.unsuccessful += obj.unsuccessful
            if obj.modified > retained_obj.modified:
                retained_obj.modified = obj.modified

            if obj.created < retained_obj.created:
                retained_obj.created = obj.created
                
            session.delete(obj)
        else:
            retained[wrapper] = obj
            obj.ip_address = wrapper.ip_address

    session.commit()
    session.connection().execute("""
        create trigger greylist_stamp
            before insert or update on greylist
            for each row
            execute procedure stamp()""")
    session.commit()

if __name__ == '__main__':
    main(*sys.argv[1:])
