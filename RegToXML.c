/*  @Description: Converts .reg files of the form:
*
*       ; (CCEID-xxxxx-x)
*       [HKEY_REG_KEY]
*       "value1"=dword:0001
*       "value2"="Help"
*       ...etc
*
*       into XML files for use with LockSmyth
*   @Author: Eli Pinkerton
*   @Version: 0.1
*   @Date: 12/28/12
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*  Should be using this instead of the same method of finding the file name at every IO stage
*   However, to do so, I'd need to malloc and free stuff, which I don't want to deal with.
*/
char *getFileName(char *cceID)
{
    char *fileName = malloc(sizeof(char) * 300);
    memset(fileName, 0, 300);

    int iterate;

    memcpy(fileName, cceID, sizeof(fileName) / sizeof(fileName[0]));
    iterate = 0;

    while(fileName[iterate] != 0)
        iterate++;

    fileName[iterate++] = '.';
    fileName[iterate++] = 'x';
    fileName[iterate++] = 'm';
    fileName[iterate++] = 'l';

    return fileName;
}

/*  Creates an XML file for some CCEID, overwriting any that previously existed.
*   Initializes the file with proper tag structure
*/
int initXMLFile(char *cceID)
{
    FILE *filePtr;
    char fileName[300];

    int iterate;

    //printf("Creating %s.xml\n", cceID);

    memcpy(fileName, cceID, sizeof(fileName) / sizeof(fileName[0]));
    iterate = 0;

    while(fileName[iterate] != 0)
        iterate++;

    fileName[iterate++] = '.';
    fileName[iterate++] = 'x';
    fileName[iterate++] = 'm';
    fileName[iterate++] = 'l';

    filePtr = fopen(fileName, "w+");

    fprintf(filePtr, "%s", "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n");
    fprintf(filePtr, "%s", "<fix>\n");
    fprintf(filePtr, "  <id>%s</id>\n", cceID);
    fprintf(filePtr, "%s", "  <name />\n");
    fprintf(filePtr, "%s", "  <exe />\n");
    fprintf(filePtr, "%s", "  <type>reg</type>\n");
    fprintf(filePtr, "%s", "  <data>\n");

    fclose(filePtr);

    return 1;
}

/* Closes the XML file for some CCEID with the proper tags */
int closeXMLFile(char *cceID)
{
    FILE *filePtr;
    char fileName[300];

    int iterate;

    //printf("Closing %s.xml\n", cceID);

    memcpy(fileName, cceID, sizeof(fileName) / sizeof(fileName[0]));
    iterate = 0;

    while(fileName[iterate] != 0)
        iterate++;

    fileName[iterate++] = '.';
    fileName[iterate++] = 'x';
    fileName[iterate++] = 'm';
    fileName[iterate++] = 'l';

    filePtr = fopen(fileName, "a");

    fprintf(filePtr, "%s", "  </data>\n");
    fprintf(filePtr, "%s", "</fix>\n");

    fclose(filePtr);

    return 1;
}

/* Writes the actual content to some XML file corresponding to the CCEID */
int writeToXML(char *cceID, char *regKey, char *regValue, char *regData, char *dataType)
{
    FILE *filePtr;
    char fileName[300];

    int iterate;

    //printf("Writing to %s.xml\n", cceID);

    memcpy(fileName, cceID, sizeof(fileName) / sizeof(fileName[0]));
    iterate = 0;

    while(fileName[iterate] != 0)
        iterate++;

    fileName[iterate++] = '.';
    fileName[iterate++] = 'x';
    fileName[iterate++] = 'm';
    fileName[iterate++] = 'l';

    filePtr = fopen(fileName, "a");

    fprintf(filePtr, "%s", "    <value>\n");
    fprintf(filePtr, "      <root>%s</root>\n", regKey);
    fprintf(filePtr, "      <name>%s</name>\n", regValue);
    fprintf(filePtr, "      <data>%s</data>\n", regData);
    fprintf(filePtr, "      <type>%s</type>\n", dataType);
    fprintf(filePtr, "%s", "    </value>\n");

    fclose(filePtr);

    return 1;
}

/* Converts certain data strings into others */
void checkData(char *regData)
{
    char *deleteWord;

    deleteWord = "*DELETE*";

    switch(regData[0])
    {
        case '-':   //Replaces "-" with "*DELETE*"
            strcpy(regData, deleteWord);
            break;
        default:
            break;
    }
}

/* Converts reg types to their "real" values */
void regTypeConversion(char *dataType)
{
    char *dword;

    dword = "REG_DWORD";

    switch(dataType[0])
    {
    case 'd':   //Currently only have to deal with dword
        strcpy(dataType, dword);
        break;
    default:
        break;
    }
}

int main(int argc, char **argv)
{
    FILE *filePtr;

    char cceID[25];     //Name of CCE vulnerability
    char keyName[300];  //Registry key
    char valueName[150];//Registry value
    char data[150];     //Registry value data
    char buffer [300];  //Stores each line from the file
    char typeName[20];  //The type of the data

    //Identifiers for the CCEID, registry key, and registry value
    char *tagCCE;
    char *tagKey;
    char *tagValue;

    tagCCE = "; (";
    tagKey = "[";
    tagValue = "=";

    //Cleanly sets up memory
    memset(typeName, 0, sizeof(typeName) / sizeof(typeName[0]));
    memset(buffer, 0, sizeof(buffer) / sizeof(buffer[0]));
    memset(cceID, 0, sizeof(cceID) / sizeof(cceID[0]));
    memset(keyName, 0, sizeof(keyName) / sizeof(keyName[0]));
    memset(valueName, 0, sizeof(valueName) / sizeof(valueName[0]));
    memset(data, 0, sizeof(data) / sizeof(data[0]));

    filePtr = fopen(argv[1], "r");

    if(filePtr != NULL)
    {
        while(fgets(buffer, sizeof(buffer) / sizeof(buffer[0]), filePtr))   //While the file still has things in it
        {
            //IFF the current line contains a CCEID
            if(strstr(buffer, tagCCE))
            {
                if(cceID[0] != 0)
                {
                    closeXMLFile(cceID);    //Close the previous CCEID if one existed. This should run every time a CCEID is found except the first
                    memset(cceID, 0, sizeof(cceID) / sizeof(cceID[0]));
                }

                sscanf(buffer, "; (%[^)])", cceID);

                initXMLFile(cceID);
            }
            //IFF the current line contains a registry key
            else if(strstr(buffer, tagKey))
            {
                memset(keyName, 0, sizeof(keyName) / sizeof(keyName[0]));
                sscanf(buffer, "[%[^\]]]", keyName);
            }
            //If the current line contains a registry key value
            else if(strstr(buffer, tagValue))
            {
                //If the key is not of type REG_SZ
                if(strstr(buffer, ":"))
                {
                    char *typePointer;
                    char *dataPointer;

                    //Clear previous vaue, data, and type
                    memset(valueName, 0, sizeof(valueName) / sizeof(valueName[0]));
                    memset(data, 0, sizeof(data) / sizeof(data[0]));
                    memset(typeName, 0, sizeof(typeName) / sizeof(typeName[0]));

                    sscanf(buffer, "\"%[^\"=]\"=%[^:]:%s", valueName, typeName, data);

                    //Convert the type to proper type
                    typePointer = (char *)&typeName;
                    regTypeConversion(typePointer);

                    //Check to see if the data matches any values we need to change (- > *DELETE*, for example)
                    dataPointer = (char *)&data;
                    checkData(dataPointer);

                    //Writes to the file with the current CCEID and key.
                    writeToXML(cceID, keyName, valueName, data, typeName);
                }
                //Otherwise, the key is of type REG_SZ
                else
                {
                    char *dataPointer;

                    //clear previous value, data, and type
                    memset(valueName, 0, sizeof(valueName) / sizeof(valueName[0]));
                    memset(data, 0, sizeof(data) / sizeof(data[0]));
                    memset(typeName, 0, sizeof(typeName) / sizeof(typeName[0]));

                    sscanf(buffer, "\"%[^\"=]\"=%s", valueName, data);

                    dataPointer = (char *)&data;
                    checkData(dataPointer);

                    writeToXML(cceID, keyName, valueName, data, typeName);
                }
            }

            //Clear the buffer
            memset(buffer, 0, sizeof(buffer) / sizeof(buffer[0]));
        }

        closeXMLFile(cceID);    //Closes the last XML file

        printf("Finished writing .xml files\n");

    }
    //File doesn't exist
    else
        printf("Could not find file.\n");



    return 0;
}
