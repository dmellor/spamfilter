#!/usr/bin/python2.4
# $Id$

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_SERIALIZABLE
import smtplib
import os
import sys

database = "spamassassin"
user = "qmail"
password = "38hb75"

def main():
    pathInfo = os.getenv("PATH_INFO")
    if pathInfo[0] != "/":
        _invalidId()
        
    deliveryId = pathInfo[1:]
    connection = psycopg2.connect(database=database, user=user,
                                  password=password)

    connection.set_isolation_level(ISOLATION_LEVEL_SERIALIZABLE)
    cursor = connection.cursor()
    try:
        cursor.execute(
            """SELECT recipient, saved_mail_id FROM saved_mail_recipients
            WHERE delivery_id = %s""",
            [deliveryId])
        if cursor.rowcount == 0:
            _invalidId()
            
        recipient, savedMailId = cursor.fetchone()

        # Determine the real recipient.
        cursor.execute(
            "SELECT delivery FROM quarantine_recipients WHERE %s ~ regexp",
            [recipient])
        if cursor.rowcount != 0:
            recipient = cursor.fetchone()[0]

        cursor.execute(
             "SELECT mail_from, contents FROM saved_mail WHERE id = %s",
             [savedMailId])
        mailFrom, msg = cursor.fetchone()
        
        # Deliver the message.
        mailServer = smtplib.SMTP("localhost")
        mailServer.sendmail(mailFrom, recipient, msg, ["BODY=8BITMIME"])
        mailServer.quit()

        cursor.execute(
            "DELETE FROM saved_mail_recipients WHERE delivery_id = %s",
            [deliveryId])
        cursor.execute(
            """SELECT COUNT(*) FROM saved_mail_recipients
            WHERE saved_mail_id = %s""",
            [savedMailId])
        number = cursor.fetchone()[0]
        if number == 0:
            cursor.execute("DELETE FROM saved_mail WHERE id = %s",
                           [savedMailId])
        
        connection.commit()
        _success()
    except:
        connection.rollback()
        raise
    
def _invalidId():
    print "Content-Type: text/html"
    print
    print "<html><head><title>Invalid Message ID</title></head>"
    print "<body><h2>An invalid message id was specified.</h2></body></html>"
    sys.exit()
    
def _success():
    print "Content-Type: text/html"
    print
    print "<html><head><title>Message Queued For Delivery</title></head>"
    print "<body>"
    print "<h2>Your message has been queued for delivery to your mailbox.</h2>"
    print "</body></html>"
    sys.exit()
    
if __name__ == "__main__":
    main()
