    node server.js //Starts the server
    node client.js --step=register --username=<YourUserName> --password=<YourPassword> --secretdata=<Secret you want to store on server> # Store the salt it returns
    node client.js --step=login --username=<YourUserName> --password=<YourPassword> --salt=<Put the salt from previous step> # It should show you the data you stored