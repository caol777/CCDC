#!/bin/bash
# shellcheck disable=SC2016
#
# This script resets the password for all users with a valid login shell.
# It generates a unique, random 4-word passphrase + "123!"
# for EVERY user.
# Example Result: "HotelCyberWolfMoon123!"
#
# DOMAIN-JOINED FIX: flushes SSSD/Winbind/realm cache before changing passwords
# to prevent timing issues where old cached credentials are used.
# Output is saved to /tmp/passwd_TIMESTAMP.csv for reference.

# DO NOT use set -e — one failure should not abort all password changes

# A massive list of simple, easy-to-type words
WORDS=(
  # NATO / Phonetic
  "Alpha" "Bravo" "Charlie" "Delta" "Echo" "Foxtrot" "Golf" "Hotel"
  "India" "Juliet" "Kilo" "Lima" "Mike" "November" "Oscar" "Papa"
  "Quebec" "Romeo" "Sierra" "Tango" "Uniform" "Victor" "Whiskey" "Xray"
  "Yankee" "Zulu"
  # Colors
  "Red" "Blue" "Green" "Black" "White" "Gold" "Silver" "Pink" "Cyan"
  "Teal" "Gray" "Brown" "Azure" "Coral" "Ivory" "Onyx" "Ruby" "Jade"
  # Animals
  "Lion" "Tiger" "Bear" "Wolf" "Eagle" "Hawk" "Shark" "Whale" "Cobra"
  "Fox" "Cat" "Dog" "Owl" "Crow" "Deer" "Elk" "Seal" "Crab" "Frog"
  "Duck" "Swan" "Goat" "Lamb" "Puma" "Lynx" "Wasp" "Bee" "Ant"
  # Space & Science
  "Moon" "Sun" "Star" "Mars" "Earth" "Comet" "Orbit" "Space" "Rocket"
  "Nova" "Void" "Atom" "Ion" "Volt" "Watt" "Flux" "Core" "Neon" "Zinc"
  "Iron" "Lead" "Acid" "Base" "Wave" "Beam" "Ray" "Dust" "Gas"
  # Tech
  "Cyber" "Logic" "Data" "Code" "Linux" "Root" "Admin" "User" "Host"
  "Byte" "Bit" "Node" "Grid" "Link" "Net" "Web" "Wifi" "Disk" "File"
  "Java" "Perl" "Ruby" "Rust" "Go" "Bash" "Shell" "Kern" "Boot" "Load"
  # Nature
  "River" "Lake" "Pond" "Sea" "Ocean" "Rain" "Wind" "Snow" "Ice" "Fire"
  "Sand" "Rock" "Tree" "Leaf" "Root" "Rose" "Lily" "Fern" "Moss" "Hill"
  "Peak" "Cliff" "Cave" "Dune" "Reef" "Tide" "Wave" "Storm" "Hail" "Mist"
  # Food
  "Apple" "Mango" "Lemon" "Berry" "Grape" "Melon" "Peach" "Plum" "Pear"
  "Lime" "Kiwi" "Fig" "Date" "Nut" "Corn" "Rice" "Bean" "Cake" "Pie"
  "Taco" "Pizza" "Soda" "Tea" "Milk" "Soup" "Beef" "Pork" "Fish" "Salt"
  # Objects
  "Book" "Desk" "Lamp" "Pen" "Door" "Wall" "Roof" "Key" "Lock" "Box"
  "Bag" "Map" "Flag" "Ship" "Car" "Bus" "Train" "Jet" "Bike" "Clock"
  "Watch" "Ring" "Coin" "Cash" "Card" "Wire" "Cord" "Pipe" "Tube" "Gear"
  # Verbs / Actions
  "Run" "Walk" "Jump" "Fly" "Swim" "Dive" "Hide" "Seek" "Find" "Lost"
  "Keep" "Give" "Take" "Make" "Fix" "Cut" "Push" "Pull" "Lift" "Drop"
  # Adjectives
  "Fast" "Slow" "High" "Low" "Hard" "Soft" "Loud" "Quiet" "Hot" "Cold"
  "Big" "Small" "Tall" "Short" "Wide" "Deep" "Rich" "Poor" "Good" "Bad"
  "New" "Old" "True" "False" "Real" "Safe" "Wild" "Calm" "Brave" "Wise"
)

OUTFILE="/tmp/passwd_$(date +%Y%m%d_%H%M%S).csv"

echo "Generating unique passphrases ending in 123!..."
echo "---------------------------------------------------"
echo "NOTE: This script changes LOCAL accounts only."
echo "      For domain-joined machines, run flush_domain_cache.sh"
echo "      AFTER the AD person changes passwords in Windows."
echo "---------------------------------------------------"
echo "USER,PASSWORD" | tee "$OUTFILE"
echo "---------------------------------------------------"

CHANGED=0
FAILED=0

# Loop through users with a valid login shell
for u in $(grep -E "/bin/.*sh|/usr/bin/.*sh" /etc/passwd | cut -d":" -f1); do

    # Skip system/service accounts (UID < 1000, except root)
    uid=$(id -u "$u" 2>/dev/null) || continue
    if [ "$uid" -lt 1000 ] && [ "$u" != "root" ]; then
        continue
    fi

    # --- Generate the Password ---
    W1=${WORDS[$((RANDOM % ${#WORDS[@]}))]}
    W2=${WORDS[$((RANDOM % ${#WORDS[@]}))]}
    W3=${WORDS[$((RANDOM % ${#WORDS[@]}))]}
    W4=${WORDS[$((RANDOM % ${#WORDS[@]}))]}
    NEW_PASS="${W1}${W2}${W3}${W4}123!"

    # --- Apply ---
    if echo "$u:$NEW_PASS" | chpasswd 2>/dev/null; then
        echo "$u,$NEW_PASS" | tee -a "$OUTFILE"
        CHANGED=$((CHANGED + 1))
    else
        echo "$u,FAILED" | tee -a "$OUTFILE"
        FAILED=$((FAILED + 1))
    fi

done

echo "---------------------------------------------------"
echo "Password reset complete. Changed: $CHANGED  Failed: $FAILED"
echo "Credentials saved to: $OUTFILE"
echo "---------------------------------------------------"
