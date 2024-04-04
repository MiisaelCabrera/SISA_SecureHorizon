
import { fetchExternalImage } from 'next/dist/server/image-optimizer';
import { writeFileSync } from 'fs';
import { NextResponse, NextRequest } from 'next/server';
import path from 'path';

export async function POST(req: NextRequest, res: NextResponse) {
        try {
            const data = await req.json(); // Obtén los datos JSON enviados desde Python
            // Realiza alguna acción con los datos recibidos, como almacenarlos en una base de datos o procesarlos
           
            const dataArray = Object.entries(data)
            const dataJSON = dataArray[0][1] as any;

            const keys = Object.keys(dataJSON);

            const finalData = keys.map((key) => {return {ip:key, quantity:dataJSON[key]}})

            const filePath = path.join(process.cwd(), 'public', 'datos.json');

            const jsonString = JSON.stringify(finalData);
            
            writeFileSync(filePath, jsonString);

            return NextResponse.json({status:200}, {status:200});
        } catch (error) {
            console.error('Error al procesar los datos:', error);
            return NextResponse.json({status:400},{status:400});
        }
    
}




export async function GET(req: NextRequest, res: NextResponse) {
    return NextResponse.json({ message: "GET" });
  }
  export async function PUT(req: NextRequest, res: NextResponse) {
    return NextResponse.json({ message: "PUT" });
  }
  export async function DELETE(req: NextRequest, res: NextResponse) {
    return NextResponse.json({ message: "DELETE" });
  }