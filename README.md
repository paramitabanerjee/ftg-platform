
First do
gradle clean build

this will create the jar

then
gradle install

this will install the jar in m2 repo

The project adding this as dependency can look for this jar in mavenCentral() as mentioned in it's build.gradle file
if it does not find it there, it can also look for it in mavenLocal()

However this jar needs to be pre-built and installed in either mavenCentral repo or mavenLocal repo
