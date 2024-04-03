import { NextResponse } from 'next/server';
import { connectionDB } from '../../../../lib/db';
import user from '../../../../models/user';

export async function GET(request, { params }) {
   try {
      connectionDB();
      const userData = await user.findById(params.id);
      if (!userData) {
         return NextResponse.json(
            { message: 'User not found' },
            { status: 404 }
         );
      }
      const data = {
         email: userData.email,
         name: userData.name,
         firstLastName: userData.firstLastName,
         secondLastName: userData.secondLastName,
         visibility: userData.visibility,
         phone: userData.phone,
         profilePicture: userData.profilePicture,
      };

      return NextResponse.json({
         data,
      });
   } catch (error) {
      return NextResponse.json({ message: error.message }, { status: 400 });
   }
}

export async function PUT(request, { params }) {
   try {
      connectionDB();
      const data = await request.json();
      const updatedUser = await user.findByIdAndUpdate(params.id, data, {
         new: true,
      });

      if (!updatedUser) {
         return NextResponse.json(
            { message: 'User not found' },
            { status: 404 }
         );
      }

      return NextResponse.json({ updatedUser });
   } catch (error) {
      return NextResponse.json({ message: error.message }, { status: 400 });
   }
}

export async function DELETE(request, { params }) {
   try {
      connectionDB();
      const userDeleted = await user.findByIdAndDelete(params.id);
      if (!userDeleted) {
         return NextResponse.json(
            { message: 'User not found' },
            { status: 404 }
         );
      }

      return NextResponse.json({
         userDeleted,
      });
   } catch (error) {
      return NextResponse.json({ message: error.message }, { status: 400 });
   }
}
