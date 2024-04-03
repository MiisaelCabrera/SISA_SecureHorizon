import { NextResponse } from "next/server";
import { connectionDB } from "../../../lib/db";
import user from "../../../models/user";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";

export async function GET() {
  const users = await user.find();

  return NextResponse.json({
    users,
  });
}

export async function POST(request) {
  try {
    connectionDB();
    const data = await request.json();
    const { email, phone } = data;

    const userEmailExists = await user.findOne({ email });
    const userPhoneExists = await user.findOne({ phone });

    const userExists = {};
    if (userEmailExists) userExists.email = userEmailExists.email;
    if (userPhoneExists) userExists.phone = userPhoneExists.phone;

    if (userExists.email || userExists.phone) {
      return NextResponse.json(
        { message: "User already exists", userExists },
        { status: 400 }
      );
    }

    if (data.password !== data.confirmPassword)
      return NextResponse.json(
        { message: "Passwords do not match" },
        { status: 400 }
      );

    data.password = await bcryptjs.hash(data.password, 10);

    if (!data.role) data.role = "user";
    if (!data.status) data.status = "active";
    if (!data.visibility) data.visibility = false;

    await new user(data).save();

    const token = jwt.sign({ email: user._id }, "clave", {
      expiresIn: "1h",
    });

    return NextResponse.json({
      token,
    });
  } catch (error) {
    return NextResponse.json(error.message, {
      status: 400,
    });
  }
}
