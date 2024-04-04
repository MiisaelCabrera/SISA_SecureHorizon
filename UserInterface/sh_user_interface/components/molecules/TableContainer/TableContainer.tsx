import { table } from "console";
import { FunctionComponent, HTMLAttributes } from "react";

interface header {
  head: string;
  id: string;
}

interface TableContainerProps extends HTMLAttributes<HTMLDivElement> {
  headers: header[];
  trafficData: any[];
}

const TableContainer: FunctionComponent<TableContainerProps> = ({
  className,
  headers,
  trafficData,
}) => {
  return (
    <table className={`w-full border ${className}`}>
      <thead className="w-full flex">
        <tr className="w-full border flex">
          {headers.map((header, index) => (
            <th className="w-1/6 border text-xl" key={index}>
              {header.head}
            </th>
          ))}
        </tr>
      </thead>
      <tbody className="flex w-full mt-4 flex-col">
        {trafficData && trafficData.map((data, index) => (
          <tr key={index} className="flex w-full ">
            {headers.map((header, index) => (
              <td className="w-1/6 my-2 text-center" key={index}>
                {data[header.id]}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
};

export default TableContainer;
