import React from "react";
import { FaEdit, FaTrash } from "react-icons/fa"; // Import icons
import { Link } from "react-router-dom";

const CartItem = ({ item, onUpdate, onDelete, onSelect, isSelected }) => {
  const handleUpdate = () => {
    if (onUpdate) {
      onUpdate(item);
    }
  };

  const handleDelete = () => {
    if (onDelete) {
      onDelete(item._id);
    }
  };

  const handleSelect = (e) => {
    if (onSelect) {
      onSelect(item._id, e.target.checked);
    }
  };

  const firstImage = item.images.length > 0 ? item.images[0] : "";

  return (
    <div className="flex items-center bg-gray-200 shadow-md rounded-lg p-5 my-3 h-60">
      <div
        className={`flex items-center justify-center w-10 h-10 rounded-full ${
          isSelected ? "bg-orange-500 border-2 border-orange-500" : "bg-white border-2 border-gray-300"
        } transition-colors duration-300`}
      >
        <input
          type="checkbox"
          checked={isSelected}
          onChange={handleSelect}
          className="w-6 h-6 accent-white cursor-pointer"
        />
      </div>

      {firstImage ? (
        <img src={firstImage} alt={item.name} className="w-16 h-16 object-cover rounded-lg mx-4" />
      ) : (
        <p className="text-gray-500 mx-4">No image available</p>
      )}

      <div className="flex flex-col flex-grow">
        <div className="flex justify-between items-center">
          <h3 className="text-2xl font-semibold text-gray-800">{item.name}</h3>
          <div className="flex items-center">
            <Link to={`/editcartitem/${item._id}`} className="text-blue-500 hover:text-blue-700 mr-2 text-2xl">
              <FaEdit />
            </Link>
            <button onClick={handleDelete} className="text-red-500 hover:text-red-700 text-2xl mr-2">
              <FaTrash />
            </button>
          </div>
        </div>
        <p className="text-gray-600">Price: Rs.{item.price}</p>
        <p className="text-gray-500">{item.description}</p>
        <div className="flex justify-between mt-2">
          <div className="flex items-center">
          {item.color ? ( // Conditionally render the color section
    <div className="flex items-center">
      <label className="mr-2">Color:</label>
      <div
        className="w-6 h-6 rounded-full"
        style={{ backgroundColor: item.color }}
      />
    </div>
  ) : null}
            
          </div>
          
          <div className="flex items-center">
            <label className="mr-2">Quantity:</label>
            <input
              type="number"
              min="1"
              value={item.count}
              readOnly
              className="w-12 border border-gray-300 rounded-md p-1 text-center bg-white"
            />
          </div>
        </div>
        <p className="text-red-600">Total Price: Rs.{item.price * item.count}</p>
      </div>
      
    </div>
  );
};

export default CartItem;
