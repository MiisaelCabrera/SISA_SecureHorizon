import HTTP from "node:http";

HTTP.createServer((request,response)=>
{
    let message = "";
    response.writeHead(200,{"Content-Type":"text/html"});
    request.on("data",(chunk)=>
    {
        console.log(chunk.toString());
        message+=chunk.toString().toUpperCase();
    });
    request.on("end",()=>{response.write(message);
        response.end();
    });
    
}
).listen(8000)