import React, { useState, useEffect } from "react";
import axios from "axios";
import { useLocation } from "react-router-dom";
import ItemCard from "../components/ItemCard";
import "../styles/itemlist.css";

const ItemList = () => {
  const [items, setItems] = useState([]);
  const [filteredItems, setFilteredItems] = useState([]);
  const location = useLocation();

  useEffect(() => {
    axios
      .get("http://localhost:3000/api/products")
      .then((res) => {
        setItems(res.data);
        filterItems(res.data, location.search);
      })
      .catch(() => {
        console.log("Error while getting data");
      });
  }, []);

  useEffect(() => {
    filterItems(items, location.search);
  }, [location.search, items]);

  const filterItems = (items, searchQuery) => {
    const query = new URLSearchParams(searchQuery).get("search") || "";

    if (query.trim()) {
      const filtered = items.filter(
        (item) =>
          item.name.toLowerCase().includes(query.toLowerCase()) ||
          item.description.toLowerCase().includes(query.toLowerCase())
      );
      setFilteredItems(filtered);
    } else {
      setFilteredItems(items);
    }
  };

  const itemlist =
    filteredItems.length === 0
      ? "No items Found"
      : filteredItems.map((item, index) => (
          <ItemCard key={index} item={item} />
        ));

  return (
    <div className="w-[100vw]"> 
    
      <div className="item-list">{itemlist}</div>
    </div>
  );
};

export default ItemList;
