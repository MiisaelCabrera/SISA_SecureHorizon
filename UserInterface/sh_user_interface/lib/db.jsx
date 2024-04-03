import { connect, connection } from "mongoose";

const connectionStatus = {
  isConnected: false,
};

export async function connectionDB() {
  if (connectionStatus.isConnected) {
    return;
  }
  const db = await connect(
    "mongodb+srv://cabreraarriaga:MT9n1KdeqJu4G69q@cluster0.y4jgcwx.mongodb.net/SecureHorizon?retryWrites=true&w=majority"
  );
  console.log(db.connection.name);
  connectionStatus.isConnected = db.connections[0].readyState;
}

connection.on("connected", () => {
  console.log("Database connected");
});

connection.on("error", (error) => {
  console.log("Error in database connection");
  console.log(error);
});
