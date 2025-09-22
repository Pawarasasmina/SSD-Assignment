import React from "react";
import { HorizontalLine } from "../components/HorizontalLine";
import { HiOutlinePlusCircle } from "react-icons/hi";

export const Overview = () => {
  return (
    <div className="flex-1 w-[80vw] bg-[#F4F4F4] p-8">
      <h1 className="font-russo text-[#212529] text-4xl">Overview</h1>
      <HorizontalLine />
      <div className="grid grid-cols-2 gap-8 mt-8">
        <Card title="Sales Performance" design="default">
          <button className="bg-[#5C646C] text-[#F4F4F4] py-2 px-4 rounded-full">
            View Graphical Representation
          </button>
        </Card>
        <Card title="Notifications" design="default" />
      </div>
      <div className="grid grid-cols-1 gap-8 mt-8">
        <Card
          title="Product Summary"
          design="default"
          actions={<HiOutlinePlusCircle className="text-[#E76F51] text-4xl" />}
        />
        <Card
          title="Promotions Overview"
          design="default"
          actions={<HiOutlinePlusCircle className="text-[#E76F51] text-4xl" />}
        />
      </div>
    </div>
  );
};

const Card = ({ title, children, actions, design }) => {
  const cardStyles = {
    default: "bg-[#F4F4F4] border-[#E76F51] border-4 rounded-lg", // Rounded corners for the entire card
  };

  const headerStyles = {
    default: "bg-[#E76F51] rounded-tl-lg", // Rounded top-left corner for the header
  };

  return (
    <div className={`relative p-6 ${cardStyles[design]}`}>
      <div
        className={`absolute top-0 left-0 w-1/2 h-12 flex items-center justify-center ${headerStyles[design]}`}
      >
        <h2 className="font-russo text-white text-center">{title}</h2>
      </div>
      <div className="mt-12 rounded-lg overflow-hidden">
        {children || <div className="bg-gray-300 h-24 rounded-lg"></div>}
      </div>
      {actions && (
        <div className="absolute top-0 right-0 mt-2 mr-2">{actions}</div>
      )}
    </div>
  );
};
