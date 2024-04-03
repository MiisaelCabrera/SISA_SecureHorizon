import { Schema, model, models } from "mongoose";

const userSchema = new Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      maxlenght: [100, "Name can not exceed 100 characters"],
      minlenght: [1, "Name must be at least 1 characters long"],
    },

    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      trim: true,
      maxlenght: [100, "Email can not exceed 100 characters"],
      minlenght: [1, "Email must be at least 1 characters long"],
      match: [
        /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/,
        "Please fill a valid email address",
      ],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
    },
    phone: {
      type: Number,
      required: [true, "Phone is required"],
      unique: true,
      trim: true,
      maxlenght: [10, "Phone can not exceed 10 characters"],
      minlenght: [10, "Phone must be at least 10 characters long"],
    },
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

export default models.User || model("User", userSchema);
