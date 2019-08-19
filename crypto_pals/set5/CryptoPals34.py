Interface between server and client


Server

Sends
* ESTABLISH:[public key part]
* METHOD DISALLOWED
* SUCCESS






Client

Sends
* ESTABLISH:(prime, generator,  public_key_part)
* MESSAGE: [IV | encrypted message]
