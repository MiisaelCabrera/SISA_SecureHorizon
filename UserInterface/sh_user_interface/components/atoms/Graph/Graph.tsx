import { FunctionComponent } from "react";

interface GraphProps {
  quantity: number;
  max: number;
}

const Graph: FunctionComponent<GraphProps> = ({ quantity, max }) => {
  const percentage = 100 * (quantity / max);
  return (
    <div className="w-full flex items-center">
      <div
        className="bg-red-500 h-8 my-4 mr-2 flex px-2"
        style={{ width: `${percentage}%` }}
      ></div>
      {quantity}
    </div>
  );
};

export default Graph;
