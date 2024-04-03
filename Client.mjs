import HTTP from "node:http";

const client = HTTP.request({hostname:"localhost",port:8000,method:"POST"},(res)=>{
    let message = "";
    res.on("data",(chunk)=> message+=chunk.toString()+" ");
    res.on("close",()=>console.log(message))
});
client.write("Hi");
client.end("Ended");