import { NextApiRequest, NextApiResponse } from 'next';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
    if (req.method === 'POST') {
        try {
            const data = req.body; // Obtén los datos JSON enviados desde Python
            // Realiza alguna acción con los datos recibidos, como almacenarlos en una base de datos o procesarlos
            console.log('Datos recibidos desde Python:', data);
            res.status(200).json({ message: 'Datos recibidos correctamente en el servidor Next.js.' });
        } catch (error) {
            console.error('Error al procesar los datos:', error);
            res.status(500).json({ message: 'Error interno del servidor.' });
        }
    } else {
        res.status(405).end(); // Método no permitido
    }
}
