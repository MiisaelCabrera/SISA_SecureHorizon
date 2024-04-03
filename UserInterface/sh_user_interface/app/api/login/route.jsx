import jwt from "jsonwebtoken";
import { NextResponse } from "next/server";
import User from "../../../models/user";
import bcryptjs from "bcryptjs";
import { connectionDB } from "../../../lib/db";

export async function POST(request) {
  try {
    connectionDB();
    const { email, password } = await request.json();

    if (!email || !password) {
      return NextResponse.json(
        { message: "Email and password are required" },
        { status: 400 }
      );
    }

    const user = await User.findOne({ email });
    if (!user) {
      return NextResponse.json({ message: "User not found" }, { status: 404 });
    }

    const passwordValidation = await bcryptjs.compare(password, user.password);

    if (!passwordValidation) {
      return NextResponse.json(
        { message: "Invalid password" },
        { status: 401 }
      );
    }

    const token = jwt.sign({ email: user._id }, "clave", {
      expiresIn: "1h",
    });
    return NextResponse.json({ token });
  } catch (error) {
    return NextResponse.json({ message: error.message }, { status: 400 });
  }
}

export async function GET(req, res) {
  return NextResponse.json({ message: "GET" });
}
export async function PUT(req, res) {
  return NextResponse.json({ message: "PUT" });
}
export async function DELETE(req, res) {
  return NextResponse.json({ message: "DELETE" });
}
