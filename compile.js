const fs = require("fs");

const compile = async () => {
  const dir = await fs.promises.opendir("library");
  for await (const dirent of dir) {
    console.log(dirent.name);
  }
};

compile();
