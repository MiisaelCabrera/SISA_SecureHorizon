import Graph from "../../atoms/Graph/Graph";
import { FunctionComponent, HTMLAttributes, useEffect, useState } from "react";

interface GraphContainerProps extends HTMLAttributes<HTMLDivElement> {
  trafficData: any[];
}

const GraphContainer: FunctionComponent<GraphContainerProps> = ({
  trafficData,
  className,
}) => {
  const [maxValue, setMaxValue] = useState(0);
  console.log(trafficData)

  useEffect(() => {
    if(trafficData){
    const sourceBytesArray = trafficData && trafficData.map((item) => item.quantity);

    setMaxValue(
      sourceBytesArray.reduce(
        (max, currentValue) => Math.max(max, currentValue),
        0
      )
    );}
  }, [trafficData]);

  return (
    <div className={` flex w-full p-6 ${className}`}>
      <div className="flex flex-col p-2">
        {trafficData &&
          trafficData.map((data, index) => (
            <div className="flex my-4 h-8" key={index + data.ip}>
              {data.ip}
            </div>
          ))}
      </div>
      <div className="w-10/12 flex-col p-2">
        {trafficData &&
          trafficData.map((data, index) => (
            <Graph
              quantity={data.quantity}
              key={index + data.ip}
              max={maxValue}
            />
          ))}
      </div>
    </div>
  );
};

export default GraphContainer;
