# Dofus Key Finder

This tool allows you to find decryption keys for dofus1 maps by using only the map's encrypted data.

You can find an explanation on how this attack works on my [blog](http://arthur.bell.al/blog/breaking-dofus-1.29.1-maps-encryption/).

## Installation

To install this tool, you can download the [last release](https://github.com/Omen-/dofus-key-finder/releases).

If your operating system does not have a binary release, but does run Go, you can build from source.

```
go get -u github.com/Omen-/dofus-key-finder/cmd/findmapkey
go install github.com/Omen-/dofus-key-finder/cmd/findmapkey
```
The binary will then be installed to `$GOPATH/bin` (or your `$GOBIN`).

## Requirements

To work, this tool need an access to a MySQL database containing all the known decrypted dofus maps.

You can find such a database (ready to use) [here](http://www.swf-redirect.com/tools/tunnel/), click on "Télécharger les maps et triggers" to download an archive containing the maps. You can then import the file maps.sql to your database.

If you do not want to use this database, you will need a database with a table named `static_maps` containing the following columns :
+ `id(int)` the id of the map
+ `date(text)` the date/version of the map
+ `mapData(text)` the encrypted data of the map in hexadecimal
+ `key(text)` the key of the map if you know it or NULL if you want to use this tool to find it 
+ `decryptedData(text)` the decrypted data of the map  or NULL if you don't have it
+ `sa(int)` subarea id of the map

### Important if you build your own database

To decrypt a map you need to have it in the database (`id`, `mapData` and `date` must be filled).

The more `decryptedData` you have the better the tool will work.

## Usage

The usage of the tool is pretty straightforward :
```
> findmapkey.exe -h
Usage of findmapkey.exe:    
  -db string  
        DB connection string. ex: -db="user:password@/dbname" (Required)      
  -maps string                                                          
        MapIDs to be decrypted. ex: -maps=1000,1001 (Required) 
  -s    Save to the database (table ouput_maps).  
  -subareas string                   
        SubAreas to be used for data source. ex: -subareas=275,276
```
**Do not add maps that are not properly decrypted (manually checked) to the static_maps table to avoid poisoning the data**

### Workflow to decrypt map X

Between each try check if the map is working
1. Try decrypting with the normal mode : `findmapkey.exe -db="user:password@/dbname" -s -maps=X.id`
2. Try decrypting with the subarea mode : `findmapkey.exe -db="user:password@/dbname" -s -maps=X -subareas=X.subareaId`
3. Try decrypting other maps in the same subarea, find the ones that are working and then add their `key` and `decryptedData` to `static_maps`. Retry 2.

If you have some troubles, you can look at the [issue tracker](https://github.com/Omen-/dofus-key-finder/issues).
## Precision

The tool will get you the correct key arround 96% percent of the time (tested on the known keys). It is not possible in my opinion to go any further than that.

When you get the output `Map(1001): 99.05% of the key found.` it means that at least 99.05% of the key is correct. The other part of the key is guessed using a statistical approach wich may fail sometimes. Even if this number is low you may still have good results.

## Contributing

If you find any bugs, please report them ! I am also happy to accept pull requests from anyone.

You can use the [issue tracker](https://github.com/Omen-/dofus-key-finder/issues) to report bugs, ask questions, or suggest new features.
